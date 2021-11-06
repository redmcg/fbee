#!/usr/bin/env python3

import sys
import argparse
import readline
import curses
import time
from fbee import FBee, FBeeSwitch, NotConnected

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
            display("usage: " + prog +  cmd)
            display(cmd + " takes no arguments")
            return INVALID_ARGLIST
    elif cmd == "raw":
        if len(args) != 1:
            display("usage: " + prog + CMD_RAW + " <bytes>")
        if len(args) > 1:
            display(CMD_RAW + " takes just one parameter. The data to send (as a byte string)")
        elif len(args) < 1:
            display(CMD_RAW + " requires one parameter. The data to send (as a byte string)")
        if len(args) != 1:
            display("bytes should only include the bytes after the control flag, for example:")
            display(prog + CMD_RAW + " 81")
            display("would get all currently connected devices")
            return INVALID_ARGLIST
    elif cmd == CMD_GET:
        if len(args) != 2:
            display("usage: " + prog + CMD_GET + " <short> <ep>")
            return INVALID_ARGLIST
    elif cmd == CMD_SET:
        if len(args) != 3:
            display("usage: " + prog + CMD_SET + " <short> <ep> <state>")
            display("Where <state> is 0 for off and 1 for on")
            return INVALID_ARGLIST
    elif cmd == CMD_ASYNC:
        if len(args) != 1:
            display("usage: " + prog + CMD_ASYNC + " <poll_interval>")
            display("Where <poll_interval> is how often to send a list command in seconds")
            return INVALID_ARGLIST
    else:
        display(cmd + " is not a valid cmd")
        return INVALID_CMD 

    return 0

def display(string, end="\n", flush=True):
    global stdscr
    if stdscr == None:
        print(string, end=end, flush=flush)
    else:
        stdscr.addstr(str(string) + end)
        if flush:
            stdscr.refresh()

def display_device(d):
    global ascii_only
    if ascii_only:
        if d.state:
            state = "|"
        else:
            state = "o"
    else:
        if d.state:
            state = "💡"
        else:
            state = "🌑"

    prefix = state + " " + d.name
    display(prefix + (" " * (30 - len(prefix))) + "[short: " + fmt(hex(d.short), 4) + " ep: " + fmt(hex(d.ep), 2) + "]")

def device_callback(device, state):
    global intcmd
    if intcmd == CMD_FETCH:
        display(".", end="", flush=True)
    elif intcmd == CMD_LIST or intcmd == CMD_ASYNC:
        display_device(device)

def raw_recv_callback(cmd, data):
    global raw_recv_pad
    if raw_recv_pad != None:
        raw_recv_pad.addstr(hex(cmd) + ": " + data.hex() + " (" + str(len(data)) + ")\n")

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
        fbee.safe_recv()
    elif cmd == CMD_GET:
        d = fbee.get_device(short, ep)
        d.poll_state()
        display_device(d)
    elif cmd == CMD_SET:
        d = fbee.get_device(short, ep)
        d.push_state(state)
        display_device(d)
    elif cmd == CMD_ASYNC:
        fbee.start_async_read(args[0], disconnect_callback = lambda f: display("Disconnected"))
    intcmd = None

def main():
    global curses_enabled

    try:
        run()
    finally:
        if curses_enabled:
            curses.endwin()

def run():
    global prog
    global fbee
    global intcmd
    global ascii_only
    global raw_recv_pad
    global stdscr
    global curses_enabled

    parser = argparse.ArgumentParser(description='Talk to hub!')
    parser.add_argument('--ip', '-i', dest='ip')
    parser.add_argument('--port', '-p', dest='port', type=int)
    parser.add_argument('--sn', '-s', dest='sn')
    parser.add_argument('--skip-device-fetch', '-d', dest='fetch_devices', action='store_false')
    parser.add_argument('--ascii-only', '-a', dest='ascii_only', action='store_true')
    parser.add_argument('--curses', '-c', dest='curses', action='store_true')
    parser.add_argument('cmd', help="The cmd to execute ('" + CMD_LIST + "', '" + CMD_RAW + "', '" + CMD_GET + "', '" + CMD_SET + "' or '" + CMD_CMDLINE + "')")
    parser.add_argument('args', nargs='*', help="The args for the cmd")

    prog = parser.prog + " "
    args = parser.parse_args()

    hexsn = args.sn
    ip = args.ip
    port = args.port
    fetch_devices = args.fetch_devices
    ascii_only = args.ascii_only
    intcmd = cmd = args.cmd
    curses_enabled = args.curses
    args = args.args

    if curses_enabled:
        stdscr = curses.initscr()
    else:
        stdscr = None

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
        display("Need to set sn, ip and port")
        exit(INVALID_CONFIG)

    hexsn = fmt(hexsn, 8)
    display("sn: " + hexsn)
    display("connecting to " + ip + ":" + str(port))
    fbee = FBee(ip, port, hexsn, [device_callback])
    fbee.connect()
    if cmd != CMD_LIST and cmd != CMD_ASYNC and fetch_devices:
        display("fetching device names", end="", flush=True)
        intcmd = CMD_FETCH
        fbee.refresh_devices()
        intcmd = cmd
        display("")

    if cmd == CMD_CMDLINE:
        prog = ""
        while True:
            if curses_enabled:
                display("> ", end="")
                line = stdscr.getstr().decode()
            else:
                try:
                    line = input("> ")
                except EOFError:
                    line = "exit"
                    display("")
                    pass

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
            elif cmd == "close":
                fbee.close()
            elif cmd == "connect":
                fbee.connect()
            else:
                ret = validate_cmd(cmd, args)
                if ret == 0:
                    try:
                        run_cmd(cmd, args)
                    except NotConnected as ex:
                        display("Not Connected: run 'connect'")
    elif cmd == CMD_ASYNC:
        t = fbee.start_async_read(args[0])
        t.join()
    else:
        run_cmd(cmd, args)

    fbee.close()

if __name__ == "__main__":
    main()
