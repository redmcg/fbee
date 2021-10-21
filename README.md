# FBee/Nue/3A Home

_This repository and package is not affiliated with Fbee._

Simple Python package for making calls to the [Nue Gateway](https://3asmarthome.com/nue-zigbee-bridge).


## Installation

```bash
pip TBA
```

## Usage

Access your nue gateway via the port 80 to obtain the s/n. 
You'll need that... 

Configure the application by creating a file named config, with the contents of:<br/>
ip=&lt;ip or host&gt;<br/>
port=&lt;port&gt;<br/>
sn=&lt;serial number&gt;<p/>
or when you run the program with:<br/>
./main.py --ip=&lt;ip or host&gt; --port=&lt;port&gt; --sn=&lt;serial number&gt; &lt;cmd&gt; [args [args ...]]

The following commands are available:<br/>
- list<br/>
- raw<br/>
- get<br/>
- set<br/>
- cmdline<br/>

The `list` command takes no arguments and will list all the devices connected to your hub.

The `raw` command takes one argument, which is the hex data (in ascii) that you want to send to the hub. This should be all the bytes after the 0xFE control byte. For example, to send the list command you would run:<br/>
./main.py raw 81

The `get` command takes two arguments. The devices short address and its endpoint. This can be obtained by the `list` command (as `short` and `ep` respectively).

The `set` command takes three arguments. The first two are the same as the `get` command, with the third being a 0 for off and a 1 for on

The `cmdline` command takes no arguments. This will leave you with a prompt in which you can type the above four commands. To exit the command line, type `exit`.
