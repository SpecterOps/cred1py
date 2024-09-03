import socket

class SOCKS5Client:
    def __init__(self, proxy_host, proxy_port):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        
        # Need a port that the relay allows connections from when forwarding UDP
        self.relay_src_port = 0x1234
        
    def _is_ip(self, host):
        try:
            socket.inet_aton(host)
            return True
        except:
            return False
        
    def _is_domain(self, host):
        return not self._is_ip(host)
    
    def close(self):
        self.proxy_sd.close()
        self.relay_sd.close()
        
    def connect(self):
        try:
            self.proxy_sd.connect((self.proxy_host, self.proxy_port))
            
            # Send Negotiation (no auth)
            self.proxy_sd.send(b'\x05\x01\x00')
            response = self.proxy_sd.recv(1024)
            if response[0] != 5:
                raise SOCKS5ClientException("Proxy couldn't connect")
            
            if response[1] != 0:
                raise SOCKS5ClientException("Proxy requires authentication")
            
            # Send UDP ASSOCIATE request
            self.proxy_sd.send(b'\x05\x03\x00\x01\x00\x00\x00\x00' + self.relay_src_port.to_bytes(2, 'big'))
            response = self.proxy_sd.recv(1024)
            if response[0] != 5 or response[1] != 0:
                raise SOCKS5ClientException(f"Error setting up UDP relay with server. Error code: {response[1]}")
            
            if response[3] == 1:
                # Extract relay IP
                self.relay_dst = socket.inet_ntoa(response[4:8])
                self.relay_dst_port = int.from_bytes(response[8:], 'big')
                
            elif response[3] == 3:
                # Extract relay domain
                domain_len = response[4]
                self.relay_dst = response[5:5+domain_len].decode()
                self.relay_dst_port = int.from_bytes(response[5+domain_len:5+domain_len+2], 'big')
                
            else:
                raise SOCKS5ClientException("Invalid relay address type")

        except Exception as e:
            raise SOCKS5ClientException(f"Error connecting to proxy: {e}")
        
    def send(self, data, destination):
        # We need a new connection (the existing TCP connection needs to stay open for the relay to also stay open)
        self.relay_sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.relay_sd.bind(('', self.relay_src_port))
        self.relay_sd.connect((self.proxy_host, self.relay_dst_port))
        
        # UDP packets are sent to the relay, which forwards them to the destination
        # They need a header prepending...
        relay_header = b'\x00\x00\x00\x01' + socket.inet_aton(destination[0]) + destination[1].to_bytes(2, 'big')
        self.relay_sd.send(relay_header + data)
        
    def recv(self, size):
        data = self.relay_sd.recv(size)
        
        if len(data) < 11:
            raise SOCKS5ClientException("Received packet is too small")
        
        if data[0] != 0 or data[1] != 0:
            raise SOCKS5ClientException("Received packet has an invalid header")
        
        # Add support for fragments (don't think CS supports this anyway)
        
        # Validate if the header has an IP or domain name
        if data[3] == 1:
            ip = socket.inet_ntoa(data[4:8])
            port = int.from_bytes(data[8:10], 'big')
            return data[10:]
            
            
        elif data[3] == 3:
            domain_len = data[4]
            domain = data[5:5+domain_len].decode()
            port = int.from_bytes(data[5+domain_len:5+domain_len+2], 'big')
            return data[5+domain_len+2:]
            
        else:
            raise SOCKS5ClientException("Received packet has an invalid header")
        
class SOCKS5ClientException(Exception):
    pass