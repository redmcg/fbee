#!/usr/bin/env python3

import sys
import argparse
import readline
from fbee import FBee, FBeeSwitch

INVALID_CONFIG=-1
INVALID_CMD=-2
INVALID_ARGLIST=-3

CMD_LIST="list"
CMD_RAW="raw"
CMD_GET="get"
CMD_SET="set"
CMD_CMDLINE="cmdline"
CMD_FETCH="fetch"
CMD_ASYNC="async"

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
    elif cmd == CMD_ASYNC:
        if len(args) != 1:
            print("usage: " + prog + CMD_ASYNC + " <poll_interval>")
            print("Where <poll_interval> is how often to send a list command in seconds")
            return INVALID_ARGLIST
    else:
        print(cmd + " is not a valid cmd")
        return INVALID_CMD 

    return 0

def print_device(d):
    if d.state:
        state = "💡"
    else:
        state = "🌑"

    prefix = state + " " + d.name
    print(prefix + (" " * (30 - len(prefix))) + "[short: " + fmt(hex(d.short), 4) + " ep: " + fmt(hex(d.ep), 2) + "]")

def device_callback(device, newdev):
    global intcmd
    if intcmd == CMD_FETCH:
        print(".", end="", flush=True)
    elif intcmd == CMD_LIST or intcmd == CMD_ASYNC:
        print_device(device)

def run_cmd(cmd, args):
    global intcmd
    intcmd = cmd
    if cmd == CMD_GET or cmd == CMD_SET:
        short = fmt(args[0], 4)
        ep = fmt(args[1], 2)

    if cmd == CMD_SET:
        state = fmt(args[2], 2)

    if cmd == CMD_LIST:
        intcmd = None
        fbee.safe_recv()
        intcmd = cmd
        fbee.refresh_devices()
    elif cmd == CMD_RAW:
        fbee.send_data(args[0])
    elif cmd == CMD_GET:
        d = fbee.get_device(short, ep)
        d.poll_state()
        print_device(d)
    elif cmd == CMD_SET:
        d = fbee.get_device(short, ep)
        d.push_state(state)
        print_device(d)
    intcmd = None

def main():
    global prog
    global fbee
    global intcmd

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
    intcmd = cmd = args.cmd
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
    fbee = FBee(ip, port, hexsn, [device_callback])
    fbee.connect()
    if cmd != CMD_LIST and cmd != CMD_ASYNC and fetch_devices:
        print("fetching device names", end="", flush=True)
        intcmd = CMD_FETCH
        fbee.refresh_devices()
        intcmd = cmd
        print("")

    if cmd == CMD_CMDLINE:
        prog = ""
        while True:
            line = input("> ")
            line = line.strip()
            line = line.split(" ")
            cmd = line[0]
            args = line[1:]
            if "short:" in args:
                args.remove("short:")
            if "ep:" in args:
                args.remove("ep:")
            if cmd == "":
                pass
            elif cmd == "exit" or cmd == "quit":
                break
            else:
                ret = validate_cmd(cmd, args)
                if ret == 0:
                    run_cmd(cmd, args)
    elif cmd == CMD_ASYNC:
        t = fbee.start_async_read(args[0])
        t.join()
    else:
        run_cmd(cmd, args)

    fbee.close()

if __name__ == "__main__":
    main()
