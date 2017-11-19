
# CS 352 project part 2
# this is the initial socket library for project 2
# You wil need to fill in the various methods in this
# library

# main libraries
import binascii
import socket as syssock
import struct
import sys

# encryption libraries
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages
global sock352portTx
global sock352portRx
# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

# this is the structure of the sock352 packet
port = -1
recv = -1
sock = (0, 0)
address = ''
curr = 0
sock352HdrStructStr = '!BBBBHHLLQQLL'

version = 0x1
# flags
SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0
SOCK352_FLAG = 0x05
opt_ptr = 0x0
protocol = 0x0
header_len = 40
checksum = 0x0
source_port = 0x0
dest_port = 0x0
sequence_no = 0x0
ack_no = 0x0
window = 0x0
data = ''

# new stuff
global communication_box
global my_secret_key
global other_host_public_key
global default_secret_key
global default_public_key

my_secret_key = -1
other_host_public_key = -1
default_secret_key = -1
default_public_key = -1


def init(UDPportTx, UDPportRx):
    global sock352portTx
    global sock352portRx

    # create the sockets to send and receive UDP packets on
    # if the ports are not equal, create two sockets, one for Tx and one for Rx
    print("Waiting for client connection")
    # create the socket
    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    recv = int(UDPportRx)
    # checks if empty
    if(UDPportTx == ''):
        port = recv
    else:
        # creates the port
        port = int(UDPportTx)
    # binds the socket to the port
    sock.bind(('', recv))
    # sets the timeout
    sock.settimeout(.2)
    return


# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(
                            keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(
                            keyInHex, nacl.encoding.HexEncoder)
        except Exception, e:
            print("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print("error: No filename presented")

    return (publicKeys, privateKeys)


class socket:

    def __init__(self):
        # your code goes here
        return

    def bind(self, address):
        # bind is not used in this assignment
        return

    def connect(self, *args):

        # example code to parse an argument list
        global sock352portTx
        global ENCRYPT
        if (len(args) >= 1):
            (host, port) = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True

        # your code goes here
        global sock, curr, sock352PktHdrData, header_len, version, opt_ptr, protocol, checksum, \
            source_port, dest_port, window, communication_box, recv
        global publicKeys, default_public_key, other_host_public_key, my_secret_key, default_secret_key

        # current sequence number set to a random int
        curr = random.randint(10, 100)

        # create the header
        header1 = struct.Struct(sock352PktHdrData)

        flags = SOCK352_SYN
        sequence_no = curr
        ack_no = 0
        payload_len = 0

        # create packet header
        header = header1.pack(version, flags, opt_ptr, protocol,
                              header_len, checksum, source_port, dest_port, sequence_no,
                              ack_no, window, payload_len)

        ACKFlag = -1

        # create the packet
        while(ACKFlag != curr):
            sock.sendto(header, (address[0], port))
            newHeader = self.packet()
            ACKFlag = newHeader[9]

        # connect
        sock.connect((address[0], port))

        curr += 1

        # Set up everything we need for encryption, if needed
        self.encrypt = False
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
                if(address[0] == 'localhost'):
                    address = ('127.0.0.1', str(receiver))
                for private_address in privateKeys:
                    if(private_address == (address[0], str(receiver))):
                        my_secret_key = privateKeys[private_address]
                        break
                if(my_secret_key == -1):
                    my_secret_key = default_secret_key
                if(my_secret_key == -1):
                    print("\tERROR. NO PRIVATE KEY FOUND FOR THIS HOST. TERMINATING.")
                    return

                for public_address in publicKeys:
                    #print("\t We are checking %s against %s for a public key." % ((address[0], transmitter), public_address))
                    if(public_address == (address[0], str(transmitter))):
                        other_host_public_key = publicKeys[public_address]
                        break
                if(other_host_public_key == -1):
                    other_host_public_key = default_public_key
                if(other_host_public_key == -1):
                    print(
                        "\tERROR. NO PUBLIC KEY FOUND FOR THE OTHER HOST. TERMINATING.")
                    return
                #print('\tThis is my secret key | their private key:\t %s | %s' % (my_secret_key, other_host_public_key))
                communication_box = Box(my_secret_key, other_host_public_key)
            else:
                print("\tInvalid encryption flag! Self-destructing now . . .")
                return
        print("Connection achieved")
        return

    def listen(self, backlog):
        # listen is not used in this assignments
        pass
        return

    def accept(self, *args):
        # example code to parse an argument list
        global ENCRYPT, sock, recv, curr, communication_box, recv
        global publicKeys, default_public_key, other_host_public_key, my_secret_key, default_secret_key
        
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
        # your code goes here
        flag = -1
        newHeader = ""

        while(flag != SOCK352_SYN):
            # call packet until we get a new connection
            newHeader = self.packet()
            flag = newHeader[1]
        curr = newHeader[8]

        ####################
        # create a new header
        header1 = struct.Struct(sock352PktHdrData)

        flags = SOCK352_ACK
        sequence_no = 0
        ack_no = curr
        payload_len = 13

        header = header1.pack(version, flags, opt_ptr, protocol,
                              header_len, checksum, source_port, dest_port, sequence_no,
                              ack_no, window, payload_len)
        ##################
        sock.sendto(header + " accepted", address)
        # Establish the encryption keys and box, if asked for
        self.encryption = False
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
                tempOtherHost = (otherHostAddress[0], str(otherHostAddress[1]))
                for private_address in privateKeys:
                    if(private_address == ('127.0.0.1', str(receiver))):
                        my_secret_key = privateKeys[private_address]
                        break
                if(my_secret_key == -1):
                    my_secret_key = default_secret_key
                if(my_secret_key == -1):
                    print("\tERROR. NO PRIVATE KEY FOUND FOR THIS HOST. TERMINATING.")
                    return (0, 0)
                for public_address in publicKeys:
                    #print("\t We are checking %s against %s for a public key." % (tempOtherHost, public_address))
                    if(public_address == tempOtherHost):
                        other_host_public_key = publicKeys[public_address]
                        break
                if(other_host_public_key == -1):
                    other_host_public_key = default_public_key
                if(other_host_public_key == -1):
                    print(
                        "\tERROR. NO PUBLIC KEY FOUND FOR THE OTHER HOST. TERMINATING.")
                    return (0, 0)
                #print('\tThis is my secret key | their private key:\t %s | %s' % (my_secret_key, other_host_public_key))
                communication_box = Box(my_secret_key, other_host_public_key)
            else:
                print("\tInvalid encryption flag! Self-destructing now . . .")
                return
        curr += 1
        print("Target acquired")
        clientsocket = socket()
       # (clientsocket, address) = (1,1)     # change this to your code
        return (clientsocket, address)

    def close(self):
        # your code goes here
        # create temporary sequence number
        temp = random.randint(10, 100)

        ###################
        # create a new header
        header1 = struct.Struct(sock352PktHdrData)

        flags = SOCK352_FIN
        sequence_no = temp
        ack_no = 0
        payload_len = 0

        header = header1.pack(version, flags, opt_ptr, protocol,
                              header_len, checksum, source_port, dest_port, sequence_no,
                              ack_no, window, payload_len)

        ####################
        # sets the timeout and waits to see if theres a FIN packet
        ACKFlag = -1
        while(ACKFlag != temp):
            try:
                sock.sendto(header, address)
            except TypeError:
                sock.send(header)
            newHeader = self.packet()
            ACKFlag = newHeader[9]
        sock.close()
        print("Connection closed")
        return

    def send(self, buffer):
        # your code goes here
        global sock, header_len, curr

        bytessent = 0       # fill in your code here
        length = len(buffer)

        while(length > 0):
            message = buffer[:255]
            # Take the top 255 bytes of the message because
            # thats the max payload we represent with a "B"
            ######################
            # create a new header
            header1 = struct.Struct(sock352PktHdrData)

            flags = 0x05
            sequence_no = curr
            ack_no = 0
            payload_len = len(message)

            pHeader = header1.pack(version, flags, opt_ptr, protocol,
                                   header_len, checksum, source_port, dest_port, sequence_no,
                                   ack_no, window, payload_len)
            ######################
            temp = 0
            ACKFlag = -1
            while(ACKFlag != curr):
                temp = sock.send(
                    pHeader + message) - header_len

                newHeader = self.packet()
                ACKFlag = newHeader[9]

            length -= 255
            buffer = buffer[255:]
            bytessent += temp
            curr += 1
        print("Segment of %d bytes was sent" % bytessent)
        return bytessent

    def recv(self, nbytes):
        # your code goes here
        global sock, data, curr
        data = ""
        bytesreceived = ""
        while(nbytes > 0):
            seq_no = -1
            # Keep checking the incoming packets until we get
            # one with the sequence number we specified eralier
            while(seq_no != curr):
                newHeader = self.packet()
                seq_no = newHeader[8]

                ###############
                # create new header
                header1 = struct.Struct(sock352PktHdrData)

                flags = SOCK352_ACK
                sequence_no = 0
                ack_no = seq_no
                payload_len = 0

                header = header1.pack(version, flags, opt_ptr, protocol,
                                      header_len, checksum, source_port, dest_port, sequence_no,
                                      ack_no, window, payload_len)
                ###############
                sock.sendto(header, address)
            if(newHeader[2] == 0x1):
                deliveredData = communication_box.decrypt(deliveredData)
            bytesreceived += data
            nbytes -= len(data)

            curr += 1
        print("Finished receiving the specified amount.")
        return bytesreceived

    # Packet class
    def packet(self):
        global sock, sock352PktHdrData, address, data
        # attempts to recv packet if not will print error message
        try:
            (data, dest) = sock.recvfrom(4096)
        except syssock.timeout:
            print("No packets received, timeout window maxed")
            head = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            return head

        # unpacks the
        (data, message) = (data[:40], data[40:])
        header = struct.unpack(sock352PktHdrData, data)
        flag = header[1]

        # checks serveral flag conditions as listed in the specs
        if(flag == SOCK352_SYN):
            address = dest
            return header
        elif(flag == SOCK352_FIN):
            ###############
            # create header
            header1 = struct.Struct(sock352PktHdrData)

            flags = SOCK352_ACK
            sequence_no = 0
            ack_no = header[8]
            payload_len = 0

            terminalHeader = header1.pack(version, flags, opt_ptr, protocol,
                                          header_len, checksum, source_port, dest_port, sequence_no,
                                          ack_no, window, payload_len)
            ###############
            sock.sendto(terminalHeader, dest)
            return header

        elif(flag == SOCK352_FLAG):
            data = message
            return header
        elif(flag == SOCK352_ACK):
            return header

        elif(flag == SOCK352_RESET):
            return header

        else:

            #####################
            # create header
            header1 = struct.Struct(sock352PktHdrData)

            flags = SOCK352_RESET
            sequence_no = header[8]
            ack_no = header[9]
            payload_len = 0

            header = header1.pack(version, flags, opt_ptr, protocol,
                                  header_len, checksum, source_port, dest_port, sequence_no,
                                  ack_no, window, payload_len)
            #####################
            if(sock.sendto(header, dest) > 0):
                print("Reset packet sent")
            else:
                print("Reset packet failed to send")
            return header
