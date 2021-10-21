#!/usr/bin/env python3

import sys
import socket
import argparse

GET_ALL_DEVICES="81"
SET_SWITCH_STATE="82"
GET_SWITCH_STATE="85"

ALL_DEVICES_RESP=0x01
SWITCH_STATUS=0x07
ACK=0x29

INVALID_CONFIG=-1
INVALID_CMD=-2
INVALID_ARGLIST=-3

CMD_LIST="list"
CMD_RAW="raw"
CMD_GET="get"
CMD_SET="set"
CMD_CMDLINE="cmdline"

devices = {}

def get(short, ep):
    return GET_SWITCH_STATE + "0002" + short[2:4] + short[0:2] + ("0" * 12) + ep + "0000"

def set_cmd(short, ep, state):
    return SET_SWITCH_STATE + "0D02" + short[2:4] + short[0:2] + ("0" * 12) + ep + "0000" + state

def recv(print_resp=True):
    global s
    global devices
    b = s.recv(2)
    while len(b) == 2:
        resp = b[0]
        b = s.recv(b[1])

        if resp == ALL_DEVICES_RESP:
            short=int.from_bytes(b[0:2], byteorder='little')
            ep=b[2]
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

            devices[hex(short) + hex(ep)] = name
            if print_resp:
                print(name + ": " + status + ", short: " + hex(short) + ", ep: " + hex(ep) + online_status)
            else:
                print(".", end="", flush=True)
        elif resp == SWITCH_STATUS:
            short=int.from_bytes(b[0:2], byteorder='little')
            ep=b[2]
            if b[3] == 1:
                status="on"
            else:
                status="off"
            key = hex(short) + hex(ep)
            if key in devices:
                name = devices[key]
            else:
                name = "[unknown]"
            if print_resp:
                print(name + ": " + status + ", short: " + hex(short) + ", ep: " + hex(ep))
        elif resp == ACK:
            print("ACK")
        else:
            if print_resp:
                print("resp: " + hex(resp) + ": " + b.hex())

        b = s.recv(2)

def safe_recv(print_resp=True):
    try:
        recv(print_resp)
    except socket.timeout as e:
        pass

def send_cmd(cmd):
    global s
    global sn
    cmd = bytes.fromhex(cmd)
    b = sn + b"\xFE" + cmd
    l = (len(b) + 2).to_bytes(2, byteorder='little')
    s.send(l + b)

def fmt(v, l):
    if len(v) > 2 and v[0:2] == "0x":
        v = v[2:]
    v = v.zfill(l)
    return v[:l]

def validate_cmd(cmd, args):
    if cmd == CMD_LIST or cmd == CMD_CMDLINE:
        if len(args) > 0:
            print("usage: " + prog +  cmd)
            print(cmd + " takes no arguments")
            return INVALID_ARGLIST
    elif cmd == "raw":
        if len(args) != 1:
            print("usage: " + prog + CMD_RAW + " <bytes>")
        if len(args) > 1:
            print(CMD_RAW + " takes just one parameter. The data to send (as a byte string)")
        elif len(args) < 1:
            print(CMD_RAW + " requires one parameter. The data to send (as a byte string)")
        if len(args) != 1:
            print("bytes should only include the bytes after the control flag, for example:")
            print(prog + CMD_RAW + " 81")
            print("would get all currently connected devices")
            return INVALID_ARGLIST
    elif cmd == CMD_GET:
        if len(args) != 2:
            print("usage: " + prog + CMD_GET + " <short> <ep>")
            return INVALID_ARGLIST
    elif cmd == CMD_SET:
        if len(args) != 3:
            print("usage: " + prog + CMD_SET + " <short> <ep> <state>")
            print("Where <state> is 0 for off and 1 for on")
            return INVALID_ARGLIST
    else:
        print(cmd + " is not a valid cmd")
        return INVALID_CMD 

    return 0

def run_cmd(cmd, args):
    global sn
    if cmd == CMD_GET or cmd == CMD_SET:
        short = fmt(args[0], 4)
        ep = fmt(args[1], 2)

    if cmd == CMD_SET:
        state = fmt(args[2], 2)

    if cmd == CMD_LIST:
        send_cmd(GET_ALL_DEVICES)
    elif cmd == CMD_RAW:
        send_cmd(args[0])
    elif cmd == CMD_GET:
        send_cmd(get(short, ep))
    elif cmd == CMD_SET:
        send_cmd(set_cmd(short, ep, state))

def main():
    global prog
    global sn
    global s

    parser = argparse.ArgumentParser(description='Talk to hub!')
    parser.add_argument('--ip', '-i', dest='ip')
    parser.add_argument('--port', '-p', dest='port', type=int)
    parser.add_argument('--sn', '-s', dest='sn')
    parser.add_argument('--skip-device-fetch', '-d', dest='fetch_devices', action='store_false')
    parser.add_argument('cmd', help="The cmd to execute ('" + CMD_LIST + "', '" + CMD_RAW + "', '" + CMD_GET + "', '" + CMD_SET + "' or '" + CMD_CMDLINE + "')")
    parser.add_argument('args', nargs='*', help="The args for the cmd")

    prog = parser.prog + " "
    args = parser.parse_args()


    hexsn = args.sn
    ip = args.ip
    port = args.port
    fetch_devices = args.fetch_devices
    cmd = args.cmd
    args = args.args

    ret = validate_cmd(cmd, args)
    if ret != 0:
        exit(ret)

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

    hexsn = fmt(hexsn, 8)
    print("sn: " + hexsn)
    print("connecting to " + ip + ":" + str(port))
    sn = bytes.fromhex(hexsn[6:8] + hexsn[4:6] + hexsn[2:4] + hexsn[0:2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.settimeout(1)
    s.connect((ip, port))
    if cmd != CMD_LIST and fetch_devices:
        print("fetching device names", end="", flush=True)
        send_cmd(GET_ALL_DEVICES)
        safe_recv(False)
        print("")

    if cmd == CMD_CMDLINE:
        prog = ""
        print("> ", end="", flush=True)
        for line in sys.stdin:
            line = line.strip()
            line = line.split(" ")
            cmd = line[0]
            args = line[1:]
            if cmd == "exit":
                break
            ret = validate_cmd(cmd, args)
            if ret == 0:
                run_cmd(cmd, args)
                safe_recv(s)
            print("> ", end="", flush=True)
    else:
        run_cmd(cmd, args)
        safe_recv(s)

    s.close()

if __name__ == "__main__":
    main()
