## Overview

This is a tool used to exploit CRED-1 over a SOCKS5 connection (with UDP support).

## How CRED-1 Works

CRED-1 can be broken down into the following steps:

1. Send a DHCP Request for the PXE image over UDP 4011
2. SCCM responds with image path and crypto keys to decrypt the referenced variables file

At this stage, two files are downloaded over TFTP:

1. 
2. 

Next CRED-1 takes the crypto keys also returned in the DHCP response, and takes one of two paths depending on the content:

1. If the crypto key is provided, password based encryption is disabled, and therefore a key derivation function is run to produce an AES key to decrypt the variables file

OR

2. If no crypto key is provided, password based encryption is enabled, and a HashCat ouotput is produced from the variables file to allow us to recover the encryption key

Once the key has been recovered (or provided), the variable file can be decrypted and the contents can be used to retrieve Network Access Account username/password.

## Usage

To use Cred1Py:

```
python ./main.py <target> <src_ip> <socks_host> <socks_port>
```

Target - The SCCM PXE server IP
SRC_IP - The IP address of the host we are running the implant on
SOCKS_HOST - The IP of the team server running SOCKS5
SOCKS_PORT - The SOCKS5 port

## How Cred1Py Works

Cred1Py attempts to perform this flow over a SOCKS5 connection, due to UDP support being provided as part of the SOCKS5 specification.

There are a few differences to tools like PxeThief as SOCKS5 limits our ability to retrieve TFTP files (we can't determine the source port used during the data transfer).

This means that the requirements for Cred1Py are:

1. An implant executing with SOCKS5 enabled
2. Ability to make a SMB connection to a distribution server (this replaces the TFTP component of PxeThief)

Once the requirements are met, Cred1Py:

1. Sends a DHCP Request for the PXE image and crypto key
2. Retrieves the crypto keying material
3. Downloads the first 512 bytes of the variables file (possible as this is sent by TFTP server without establishing a TID which needs source port)
4. Outputs either a crypto key, or a hashcat hash, as well as the path to the boot variable file returned via DHCP

At this point, we will need to use our C2 to download the boot variable file, for example in CobaltStrike we can use:

```
download \\sccmserver.lab.local\REMINST\SMSTemp\BootFileName.boot.var
```

We then use PxeThiefy to decrypt the `boot.var` file with our recovered key:

```
python ./pxethiefy.py decrypt -f /tmp/out.boot.var PASSWORD_HERE
```



