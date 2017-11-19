# CS 352 project part 2 
# this is the initial socket library for project 2 
# You wil need to fill in the various methods in this
# library 

# main libraries 
import binascii
import socket as syssock
import struct
import sys
import random

# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

SOCK352_SYN = 0x01  
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0xA0
SOCK352_FLAG = 0x05
transmitter = -1
recv = -1
sock = (0,0)
address = ""
curr = 0
sock352PktHdrData = "!BBBBHHLLQQLL"
version = 0x1
protocol = 0x0
checksum = 0x0
source_port = 0x0
dest_port = 0x0
window = 0x0
header_len = 40
data = ""

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

global box
global secretkey
global addressPkey
global defaultSKey
global defaultPKey

secretkey = -1
addressPkey = -1
defaultSKey = -1
defaultPKey = -1

# this is the structure of the sock352 packet 
#sock352HdrStructStr = '!BBBBHHLLQQLL'
def init(UDPportTx,UDPportRx):
    global sock, transmitter, recv
    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    recv = int(UDPportRx)
    if(UDPportTx == ''):
        transmitter = recv
    else:
        transmitter = int(UDPportTx)
    sock.bind( ('', recv) )
    sock.settimeout(2)
    return

    
# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex, privateKeysHex, publicKeys, privateKeys
    global defaultSKey, defaultPKey
    
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    if(host == 'localhost'):
                        host = '127.0.0.1'
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                        if(host == '*' and port == '*'):
                            defaultSKey = privateKeys[(host,port)]
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
                        if(host == '*' and port == '*'):
                            defaultPKey = publicKeys[(host,port)]
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
        print ("error: No filename presented")             
    return (publicKeys,privateKeys)

class socket:
    
    def __init__(self):
        # your code goes here 
        return 
        
    def bind(self,address):
        # bind is not used in this assignment 
        return

    def connect(self,*args):

        global sock352portTx, ENCRYPT, sock, curr, box, recv
        global publicKeys, defaultPKey, addressPkey, secretkey, defaultSKey
        address = []
        # example code to parse an argument list 
        if (len(args) >= 1): 
            address = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
                
        print("Initiating a conection" )
        
        curr = int( random.randint(20, 100) )
        header = self.__make_header(0x0,0x01, curr, 0, 0)
        ackFlag = -1
        while(ackFlag != curr ):
            sock.sendto(header,(address[0], transmitter))  
            newHeader = self.__sock352_get_packet()
            ackFlag = newHeader[9]
        sock.connect( (address[0], transmitter) )
        curr += 1

        self.encrypt = False
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
                if(address[0] == 'localhost'):
                    address = ('127.0.0.1', str(recv) )
                for private_address in privateKeys:
                    if(private_address == (address[0],str(recv))):
                        secretkey = privateKeys[private_address]
                        break
                if(secretkey == -1):
                    secretkey = defaultSKey
                if(secretkey == -1):
                    print("\tERROR. NO PRIVATE KEY FOUND FOR THIS HOST. TERMINATING.")
                    return
                
                for public_address in publicKeys:
                     if(public_address == (address[0], str(transmitter)) ):
                        addressPkey = publicKeys[public_address]
                        break
                if(addressPkey == -1):
                    addressPkey = defaultPKey
                if(addressPkey == -1):
                    print("\tERROR. NO PUBLIC KEY FOUND FOR THE OTHER HOST. TERMINATING.")
                    return
                box = Box(secretkey,addressPkey)
            else:
                print ("\tInvalid encryption flag! Self-destructing now . . .")
                return
        return

    def listen(self,backlog):
        # listen is not used in this assignments 
        pass
    
    def accept(self,*args):
         # your code goes here 
        global ENCRYPT, sock, recv, curr, box, recv
        global publicKeys, defaultPKey, addressPkey, secretkey, defaultSKey
        flag = -1
        newHeader = ""
        while(flag != 0x01):
            newHeader = self.__sock352_get_packet()
            flag = newHeader[1]
        curr = newHeader[8]
        header = self.__make_header(0x0,0x04,0,curr,13)
        sock.sendto(header+"I accept you.", address)
        print('\tWe are connecting to %s' % str(address) )
        self.encryption = False
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
                tempOtherHost = (address[0],str(address[1]))
                for private_address in privateKeys:
                    if(private_address == ('127.0.0.1',str(recv))):
                        secretkey = privateKeys[private_address]
                        break
                if(secretkey == -1):
                    secretkey = defaultSKey
                if(secretkey == -1):
                    print("No private key found")
                    return (0,0)
                for public_address in publicKeys:
                    if(public_address == tempOtherHost ):
                        addressPkey = publicKeys[public_address]
                        break
                if(addressPkey == -1):
                    addressPkey = defaultPKey
                if(addressPkey == -1):
                    print("No public key found")
                    return (0,0)
                box = Box(secretkey,addressPkey)
            else:
                return
        curr += 1
        clientsocket = socket()
        return (clientsocket,address)

    def close(self):
        # your code goes here 
        terminal_no = random.randint(7,19)
        header = self.__make_header(0x0,0x02, terminal_no, 0, 0)
        ackFlag = -1
        while(ackFlag != terminal_no):
            try:
                sock.sendto(header, address)
            except TypeError:
                sock.send(header)
            newHeader = self.__sock352_get_packet()
            ackFlag = newHeader[9]
        sock.close()
        return

    def send(self,buffer):
        # your code goes here 
        global sock, header_len, curr, box
        
        bytesSent = 0
        msglen = len(buffer)
        while(msglen > 0):
            parcel_len = 2047
            optionBit = 0x0
            encryption_filler = 0
            parcel = ""
            if(self.encrypt):
                encryption_filler = 40
                parcel_len = parcel_len - encryption_filler
                parcel = buffer[:parcel_len]
                nonce = nacl.utils.random(Box.NONCE_SIZE)
                parcel = box.encrypt(parcel, nonce)
                optionBit = 0x1
            else:
                parcel = buffer[:parcel_len]
            parcelHeader = self.__make_header(optionBit,0x03,curr,0,parcel_len )
            tempBytesSent = 0
            ackFlag = -1
            while(ackFlag != curr):
                tempBytesSent = sock.send(parcelHeader+parcel) - header_len - encryption_filler
                newHeader = self.__sock352_get_packet()
                ackFlag = newHeader[9]
            msglen -= parcel_len
            buffer = buffer[parcel_len:]
            bytesSent += tempBytesSent
            curr += 1
        print("Bytes sent = %d" % bytesSent)
        return bytesSent

    def recv(self,nbytes):
        # your code goes here
        global sock, data, curr
        
        data = ""
        fullMessage = ""
        print("\tReceiving %d bytes" % (nbytes))
        while(nbytes > 0):
            seq_no = -1
            while(seq_no != curr):
                newHeader = self.__sock352_get_packet()
                seq_no = newHeader[8]
                header = self.__make_header(0x0,0x04, 0,seq_no,0)
                sock.sendto(header, address)
            if(newHeader[2] == 0x1):
                data = box.decrypt(data)
            fullMessage += data
            nbytes -= len(data)
            curr += 1
        print("Found")
        return fullMessage

    def  __sock352_get_packet(self):
        global sock, sock352PktHdrData, address, data
        try:
            (data, senderAddress) = sock.recvfrom(4096)
        except syssock.timeout:
            print("\t\tNo packets received before the timeout!")
            z = [0,0,0,0,0,0,0,0,0,0,0,0]
            return z
        (data_header, data_msg) = (data[:header_len],data[header_len:])
        header = struct.unpack(sock352PktHdrData, data_header)
        flag = header[1]
        if(flag == 0x01):
            address = senderAddress
            return header
        elif(flag == 0x02):
            terminalHeader = self.__make_header(0x0,0x04,0,header[8],0)
            sock.sendto(terminalHeader, senderAddress)
            return header
        elif(flag == 0x03):
            data = data_msg
            return header
        elif(flag == 0x04):
            return header
        elif(flag == 0x08):
            return header
        else:
            header = self.__make_header(0x0,0x08,header[8],header[9],0)
            if(sock.sendto(header,senderAddress) > 0):
                print("Sent a reset packet")
            else:
                print("Reset packet failed")
            return header
    
    def  __make_header(self, givenOption, givenFlag, givenSeqNo, givenAckNo, givenPayload):
        global sock352PktHdrData, header_len, version, protocol
        global checksum, source_port, dest_port, window

        opt_ptr = givenOption
        flags = givenFlag
        sequence_no = givenSeqNo
        ack_no = givenAckNo
        payload_len = givenPayload
        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)
        return udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol,
            header_len, checksum, source_port, dest_port, sequence_no,
            ack_no, window, payload_len)