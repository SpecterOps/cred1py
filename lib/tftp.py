from lib import socks
import struct

class TFTPClient:
    def __init__(self, target, port, socks_client):
        self.target = target
        self.port = port
        self.socks_client = socks_client
        
    def get_file(self, filename):
        self.socks_client.send(b'\x00\x01' + bytes(filename, 'ascii')  + b'\x00' + b'octet' + b'\x00', (self.target, self.port))
        data = self.socks_client.recv(9076)

        (opcode, block) = struct.unpack(">HH", data[:4])
        if opcode != 3:
            print("[!] Invalid opcode from TFTP server")
            return
        
        filedata = b''
        
        # Iterate through data blocks
        while True:
            self.socks_client.send(b'\x00\x04' + block.to_bytes(2, 'big'), (self.target, self.port))
            data = self.socks_client.recv(9076)
            (opcode, block) = struct.unpack(">HH", data[:4])
            
            if opcode != 3:
                print("[!] Invalid opcode from TFTP server")
                return None
            
            filedata += data[4:]
            
            # No point carrying on as we can't ack the request, so just return the first 516 bytes
            return filedata
            
            # if len(data) <= 516:        
            #     # End of file
            #     return filedata

        #return filedata