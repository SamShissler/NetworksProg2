import Network
import argparse
from time import sleep
import hashlib


class Packet:
    # the number of bytes used to store packet length
    seq_num_s_length = 10
    length_s_length = 10
    ack_s_length = 3
    # length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_s, flag="   "):
        self.seq_num = seq_num
        self.msg_s = msg_s
        self.flag = flag

    @classmethod
    def from_byte_s(self, byte_s):
        if Packet.corrupt(byte_s):
            return None
        # extract the fields
        seq_num = int(byte_s[Packet.length_s_length: Packet.length_s_length + Packet.seq_num_s_length])
        ack = byte_s[Packet.length_s_length + Packet.seq_num_s_length:
        Packet.length_s_length + Packet.seq_num_s_length + Packet.ack_s_length]
        msg_s = byte_s[Packet.length_s_length + Packet.seq_num_s_length +
                       Packet.ack_s_length + Packet.checksum_length:]
        return self(seq_num, msg_s, ack)

    def get_byte_s(self):
        # convert sequence number of a byte field of seq_num_s_length bytes
        seq_num_s = str(self.seq_num).zfill(self.seq_num_s_length)
        # convert length to a byte field of length_s_length bytes
        length_s = str(self.length_s_length + len(seq_num_s) + self.checksum_length +
                       len(self.msg_s)).zfill(self.length_s_length)
        # compute the checksum
        checksum = hashlib.md5((length_s + seq_num_s + self.msg_s).encode('utf-8'))
        checksum_s = checksum.hexdigest()
        # compile into a string
        return length_s + seq_num_s + self.flag + checksum_s + self.msg_s

    @staticmethod
    def is_nak(self):
        if self.flag is "NAK":
            return True
        return False

    @staticmethod
    def is_ack(self):
        if self.flag is "ACK":
            return True
        return False

    @staticmethod
    def corrupt(byte_s):
        # extract the fields
        length_s = byte_s[0:Packet.length_s_length]
        seq_num_s = byte_s[Packet.length_s_length: Packet.length_s_length + Packet.seq_num_s_length]
        ack_s = byte_s[Packet.length_s_length + Packet.seq_num_s_length : Packet.length_s_length +
              Packet.seq_num_s_length + Packet.ack_s_length]
        checksum_s = byte_s[Packet.length_s_length + Packet.seq_num_s_length + Packet.ack_s_length:
        Packet.seq_num_s_length + Packet.length_s_length + Packet.checksum_length + Packet.ack_s_length]
        msg_s = byte_s[Packet.seq_num_s_length + Packet.seq_num_s_length + ack_s + Packet.checksum_length:]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_s + seq_num_s + ack_s + msg_s).encode('utf-8'))
        computed_checksum_s = checksum.hexdigest()
        # and check if the same
        return checksum_s != computed_checksum_s


class RDT:
    # latest sequence number used in a packet
    seq_num = 1
    last_recieved = 1
    # buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_s, server_s, port):
        self.network = Network.NetworkLayer(role_s, server_s, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_s):
        p = Packet(self.seq_num, msg_s)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_s())

    def rdt_1_0_receive(self):
        ret_s = None
        byte_s = self.network.udt_receive()
        self.byte_buffer += byte_s
        # keep extracting packets - if reordered, could get more than one
        while True:
            # check if we have received enough bytes
            if len(self.byte_buffer) < Packet.length_s_length:
                return ret_s  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_s_length])
            if len(self.byte_buffer) < length:
                return ret_s  # not enough bytes to read the whole packet
            # create packet from buffer content and add to return string
            p = Packet.from_byte_s(self.byte_buffer[0:length])
            ret_s = p.msg_s if (ret_s is None) else ret_s + p.msg_s
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration

    def rdt_2_1_send(self, msg_s):
        p = Packet(self.seq_num, msg_s)

        self.network.udt_send(p.get_byte_s())
        rec_msg = None
        while rec_msg is None:
            rec_msg = self.rdt_2_1_receive()
            if rec_msg is None or Packet.is_nak(rec_msg):
                self.network.udt_send(p.get_byte_s())
            if rec_msg is not None and Packet.is_ack(rec_msg):
                self.seq_num = (self.seq_num + 1) % 2
                return

    def rdt_2_1_receive(self):
        ret_s = None
        byte_s = self.network.udt_receive()
        self.byte_buffer += byte_s
        while True:
            if len(self.byte_buffer) < Packet.length_s_length:
                return ret_s
            length = int(self.byte_buffer[:Packet.length_s_length])
            if len(self.byte_buffer) < length:
                return ret_s
            p = Packet.from_byte_s(self.byte_buffer[0:length])
            if p is None:
                nextpckt = Packet(self.seq_num, "", "NAK")
                self.network.udt_send(nextpckt.get_byte_s())
            else:
                ret_s = p.msg_s if (ret_s is None) else ret_s + p.msg_s
                self.byte_buffer = self.byte_buffer[length:]

    def rdt_3_0_send(self, msg_s):
        p = Packet(self.seq_num, msg_s)
        self.seq_num = (self.seq_num + 1) % 2
        self.network.udt_send(p.get_byte_s())
        nxtpckt = Packet.get_packet()
        if nxtpckt is not None and nxtpckt.seq_num == self.seq_num:
            rdt_3_0_receive()
        else:
            rdt_3_0_send(msg_s)

    def rdt_3_0_receive(self):
        p = Packet.get_packet()
        if p is not None and p.seq_num == self.seq_num:
            nextpckt = Packet(self.seq_num, "", "ACK")
            self.network.udt_send(nextpckt)
        else:
            nextpckt = Packet(self.seq_num, "", "NAK")
            self.network.udt_send(nextpckt)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
