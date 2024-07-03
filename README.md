
# Packet Transmitter
Utility to create and send raw packets based on an input specfile

## Current Capabilities
Construct and serialize packet based on specified structure and input values.
Encapsulate serialized packet in ip datagram.
Send IP datagram containing constructed packet payload to a specified IPv4 address.

## Build
      ```
      cd src
      make build
      ``` 
Build system is currently very basic. Binary named `pt` will be created in src directory. 

## Basic Use
`./pt --packet-type tcp --spec-dir ../specfiles --dest-ip 127.0.0.1 --src-ip 127.0.0.1`    
The above command will continuously send packets based on the specfile located at `../specfiles/tcp` to `127.0.0.1` from `127.0.0.1`

##### Additional options
`--interval <milliseconds>` number of milliseconds to wait between packet sends, defautl value of 0 continuously sends packets    
`--num-packets <num>` number of packets to send, default value of 0 sends packets until program is stopped    

## Specfile Format
The specfiles need to follow a specific format for the packet to be correctly constructed. See example tcp specfile

Specfiles can contain 3 sections: 
#### Packet header 
Is always the first section of the spec file. First line must contain the max size of the header in octets. Following lines contain attributes that make up the header.

#### Pseudo header
Always begins with `PSUEDOHEADER`. Not required. Must come after the packet header. Must begin with max size of the pseudo header in octets. If the pseudoheader exists it will be used in the auto calculation of the packet checksum. Attributes follow the same format as those in the packet header.

#### DATA
Always begins with `DATA`. Not required. If it exists it will contain the packet payload. Size does not need to be provided. Must be the last section.

#### Attribute format
Each attribute follows this exact format: `<name> <length of value in octets> <value in hex>`
The value must be Big-Endian.
If the attribute has a variable size it must follow this format followed by each of its children prepended with a tab or space character.
```
<name> -1
      <len child 1> <value child 1>
      <len child 2> <value child 2>
```
If a variable length attribute is specified but no children exist the attribute will be ignored.

#### Special Character
`$` denotes the checksum whose value should be replaced with the auto calculated checksum.     
`^` denotes the pseudo header value which should be replaced with the real length of the packet header. The real length of the packet header is the sum of all attribute and child attribute lengths, NOT the max packer header length.     

#### Example Specfile
```
60
source-port 2 0x0050
destination-port 2 0x0050
sequence-number 4 0x00000000
acknowledgement-number 4 0x00000000
data-offset-reserved-control-bits 2 0x5002
window-size 2  0x16D0
$checksum 2 0x0000
urgent-pointer 2 0x0000
options -1
      1 0x00
      1 0x03
padding -1
PSEUDOHEADER
55
source-address 4 0x7F000001
destination-address 4 0x7F000001
reserved 1 0x00
protocol 1 0x00
^tcp-length 2 0x0100
DATA
hello
```

Notes on specfile example:
- 60 is the max size of the packet header.
- Value of checksum will be replaced with the calculated checksum
- padding will be ignored since it has no children
- 55 is the max size of the pseudoheader
- Value of tcp-length in the pseudoheader will be replaced with the real length of the packet header. 22 in this case 


## Current Limitations
- Can only send to IPv4 Addresses.
- DATA must be the last section of the specfile. Do not support attributes after the packet data.
- Sends on top of IP datagram. Sending/encapsulating in other layers currently not supported.
- Checksum length must be 2 octets for auto calculation.

```
packet-size
attr1-name


      +-----------------------------------------------------+
      |   Withdrawn Routes Length (2 octets)                |
      +-----------------------------------------------------+
      |   Withdrawn Routes (variable)                       |
      +-----------------------------------------------------+
      |   Total Path Attribute Length (2 octets)            |
      +-----------------------------------------------------+
      |   Path Attributes (variable)                        |
      +-----------------------------------------------------+
      |   Network Layer Reachability Information (variable) |
      +-----------------------------------------------------+
```

## Additional work
- [ ] Allow auto setting of src IP
- [ ] Check for memory leaks. Refactor a few functions to be allocator must also free.
- [ ] Allow encapsulation in TCP/UDP instead of IP
- [ ] Allow for variable size checksum, only 16bit checksum currently supported
- [x] Optimize send of packet. Currently read specfile and construct packet everytime. Optimize to only update packet when specfile changes.
- [ ] Add testing, unittests
- [ ] Allow user to specify specfile sections in any order.
- [ ] Support IPv6







