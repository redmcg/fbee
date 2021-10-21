#!/usr/bin/env python3

import socket
import argparse

GET_ALL_DEVICES="81"
SET_SWITCH_STATE="82"


INVALID_CONFIG=-1
INVALID_CMD=-2
INVALID_ARGLIST=-3


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
            if b[9+b[8]] == 0:
                online_status=" (offline)"
            else:
                online_status=""
            if name == "":
                name = "[" + b[19:19+b[18]].decode() + "]"
            print(name + ": " + status + ", short: 0x" + short.to_bytes(2, byteorder='big').hex() + ", ep: 0x" + ep + online_status)
            b = s.recv(2)

    if cmd[0] == int(SET_SWITCH_STATE, 16):
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
            if b[9+b[8]] == 0:
                online_status=" (offline)"
            else:
                online_status=""
            if name == "":
                name = "[" + b[19:19+b[18]].decode() + "]"
            print(name + ": " + status + ", short: 0x" + short.to_bytes(2, byteorder='big').hex() + ", ep: 0x" + ep + online_status)
            b = s.recv(2)


def main():
    parser = argparse.ArgumentParser(description='Talk to hub!')
    parser.add_argument('--ip', '-i', dest='ip')
    parser.add_argument('--port', '-p', dest='port', type=int)
    parser.add_argument('--sn', '-s', dest='sn')
    parser.add_argument('cmd', help="The cmd to execute ('list' or 'raw')")
    parser.add_argument('args', nargs='*', help="The args for the cmd")

    prog = parser.prog
    args = parser.parse_args()

    hexsn = args.sn
    ip = args.ip
    port = args.port
    cmd = args.cmd
    args = args.args

    if hexsn == None or ip == None or port == None:
        try:
            with open('config') as config:
                for line in config:
                    name, val = line.partition("=")[::2]
                    val = val.strip()
                    if name == "ip" and ip == None:
                        ip = val
                    elif name == "port" and port == None:
                        port = int(val)
                    elif name == "sn" and hexsn == None:
                        hexsn = val
        except IOError as e:
            pass

    if hexsn == None or ip == None or port == None:
        print("Need to set sn, ip and port")
        exit(INVALID_CONFIG)

    if cmd == "list":
        if len(args) > 0:
            print("usage: " + prog + " list")
            print("list takes no arguments")
            exit(INVALID_ARGLIST)
    elif cmd == "raw":
        if len(args) != 1:
            print("usage: " + prog + " raw <bytes>")
        if len(args) > 1:
            print("raw takes just one parameter. The data to send (as a byte string)")
        elif len(args) < 1:
            print("raw requires one parameter. The data to send (as a byte string)")
        if len(args) != 1:
            print("bytes should only include the bytes after the control flag, for example:")
            print(prog + " raw 81")
            print("would get all currently connected devices")
            exit(INVALID_ARGLIST)
    else:
        print(cmd + " is not a valid cmd")
        exit(INVALID_CMD)

    print("sn: " + hexsn)
    print("connecting to " + ip + ":" + str(port))
    sn = bytes.fromhex(hexsn)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((ip, port))
    if cmd == "list":
        send_cmd(s, sn, GET_ALL_DEVICES)
    elif cmd == "raw":
        send_cmd(s, sn, args[0])

    s.close()

if __name__ == "__main__":
    main()
