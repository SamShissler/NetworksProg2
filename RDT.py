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
        length = Packet.length_s_length
        seq_num = Packet.seq_num_s_length
        ack = Packet.ack_s_length
        checksum = Packet.checksum_length

        seq_num = int(byte_s[length: length + seq_num])
        ack = byte_s[length + seq_num:length + seq_num + ack]
        msg_s = byte_s[length + seq_num + ack + checksum:]
        return self(seq_num, msg_s, ack)

    def get_byte_s(self):
        # convert sequence number of a byte field of seq_num_s_length bytes
        seq_num_s = str(self.seq_num).zfill(self.seq_num_s_length)
        # convert length to a byte field of length_s_length bytes
        length_s = str(self.length_s_length +
                       self.seq_num_s_length +
                       len(self.flag) +
                       self.checksum_length +
                       len(self.msg_s))
        # compute the checksum
        checksum = hashlib.md5((length_s + seq_num_s + self.flag + self.msg_s).encode('utf-8'))
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
        ack_s = byte_s[Packet.length_s_length + Packet.seq_num_s_length: Packet.length_s_length +
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
        print("SENT PACKET")
        rec_pkt = None
        while rec_pkt == None:
            rec_pkt = self.rdt_2_1_get_packet()

            if rec_pkt.flag == "NAK":
                print("NAK")
                self.network.udt_send(p.get_byte_s())
            elif Packet.corrupt(rec_pkt):
                print("CORRUPT: EXPECTED ACK OR NAK")
                if rec_pkt.flag == "   ":

                    nextpckt = Packet(self.seq_num, "", "ACK")
                    self.network.udt_send(nextpckt.get_byte_s())
                else:
                    self.network.udt_send(p.get_byte_s())
            elif rec_pkt.flag == "ACK":
                print("ACK")
                self.seq_num = (self.seq_num + 1) % 2
                return
            else:
                print("GOT MESSAGE?")

    def rdt_2_1_receive(self):
        print("LISTENING")
        p = self.rdt_2_1_get_packet()

        if p.flag == "   ":
            print("SENT ACK")
            nextpckt = Packet(self.seq_num, "", "ACK")
            self.network.udt_send(nextpckt.get_byte_s())
        else:
            print(p.flag)
            print(p.msg_s)

        return p.msg_s

    def rdt_2_1_get_packet(self):
        p = self.extract_packet()
        while p is None:
            self.byte_buffer += self.network.udt_receive()
            p = self.extract_packet();
        return p

    def extract_packet(self):
        print(self.byte_buffer)
        if (len(self.byte_buffer) < Packet.length_s_length):
            return None
        length = int(self.byte_buffer[:Packet.length_s_length])
        if len(self.byte_buffer) < length:
            return None

        p = Packet.from_byte_s(self.byte_buffer[0:length])
        self.byte_buffer = self.byte_buffer[length:]
        return p

    def rdt_3_0_send(self):
        p = Packet(self.seq_num, msg_s)

        self.network.udt_send(p.get_byte_s())
        print("SENT PACKET")
        rec_pkt = None
        start_time = time.time()
        while rec_pkt == None and time.time() - start_time < 200:
            rec_pkt = self.rdt_2_1_get_packet()

            if rec_pkt.flag == "NAK":
                print("NAK")
                self.network.udt_send(p.get_byte_s())
            elif Packet.corrupt(rec_pkt):
                print("CORRUPT: EXPECTED ACK OR NAK")
                if rec_pkt.flag == "   ":

                    nextpckt = Packet(self.seq_num, "", "ACK")
                    self.network.udt_send(nextpckt.get_byte_s())
                else:
                    self.network.udt_send(p.get_byte_s())
            elif rec_pkt.flag == "ACK":
                print("ACK")
                self.seq_num = (self.seq_num + 1) % 2
                return
            else:
                print("GOT MESSAGE?")
        if rec_pkt is None:
            self.rdt_3_0_send()

    def rdt_3_0_receive(self):
        return self.rdt_2_1_receive()


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
