#!/usr/bin/env python3

import socket
import argparse

GET_ALL_DEVICES="81"


def send_cmd(s, sn, cmd):
    cmd = bytes.fromhex(cmd)
    b = sn + b"\xFE" + cmd
    l = (len(b) + 2).to_bytes(2, byteorder='little')
    s.send(l + b)

    if cmd[0] == int(GET_ALL_DEVICES, 16):
        b = s.recv(2)
        while len(b) == 2 and b[0] == 1:
            b = s.recv(b[1])
            short=int.from_bytes(b[0:2], byteorder='little')
            ep=b[2:3].hex()
            if b[7] == 1:
                status="on"
            else:
                status="off"
            name=b[9:9+b[8]].decode()
            if name == "":
                name = "[" + b[19:19+b[18]].decode() + "]"
            print(name + ": " + status + ", short: 0x" + short.to_bytes(2, byteorder='big').hex() + ", ep: 0x" + ep)
            b = s.recv(2)

def main():
    parser = argparse.ArgumentParser(description='Talk to hub!')
    parser.add_argument('--ip', '-i', dest='ip', nargs=1, required=True)
    parser.add_argument('--port', '-p', dest='port', type=int, nargs=1, required=True)
    parser.add_argument('--serial-number', '-s', dest='sn', nargs=1, required=True)
    args = parser.parse_args()

    sn = bytes.fromhex(args.sn[0])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((args.ip[0], args.port[0]))
    send_cmd(s, sn, GET_ALL_DEVICES)
    s.close()

if __name__ == "__main__":
    main()
