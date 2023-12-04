#!/usr/bin/env python3
import os
import sys
import argparse

PNG_HEADER = bytearray(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A')

def parse_cli():
    """Parse cli args"""
    parser = argparse.ArgumentParser(
        description= "Parse Executable to make it ExeWho2 ready"
    )
    parser.add_argument('path_to_exe')
    parser.add_argument('-k', '--key', help="Encryption Key", required=False)
    args = parser.parse_args()
    d_args = {
        'exe_path': args.path_to_exe,
        'key': args.key
    }
    return d_args

def encrypt_me(f_bytes, keystr):
    """Encrypt payload bytes with a key"""
    key = bytearray()
    key.extend(map(ord, keystr))
    xor_byte_array = bytearray()
    sizef = len(f_bytes)
    xor_byte_array = bytearray(sizef)

    for i in range(sizef):
        xor_byte_array[i] = f_bytes[i] ^ key[i%len(keystr)]

    print(f"[i] Encrypted {sizef} bytes")
    return xor_byte_array

def main():
    """Main function to call it all"""

    # Parse CLI args
    cli_args = parse_cli()

    payload_path = os.path.abspath(cli_args["exe_path"])
    if not os.path.exists(payload_path):
        print(f"[!] Path does not exist:\t{payload_path}", file=sys.stderr)
        sys.exit(-1)

    if not os.path.isfile(payload_path):
        print(f"[i] Path is not a file:\t{payload_path}", file=sys.stderr)
        sys.exit(-1)

    b_payload = bytearray()
    with open(payload_path, 'rb') as f:
        payload = f.read()
        # Encrypt payload
        if cli_args['key']:
            """Decrypt"""
            payload = encrypt_me(payload, cli_args['key'])
        b_payload = bytearray(PNG_HEADER + payload)

    with open(payload_path+'.png', 'wb') as f:
        f.write(b_payload)
  

if __name__=='__main__':
    main()