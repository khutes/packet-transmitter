
## Format of spec files

For any given spec the file willk have the following genral format of the packet size on the first line followed each attribute on its own line.

Attributes with a fixed size will use the format below: 
`name size value`

Attributes of variable length will use the format below:
`name -1 length-child value-child`


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


## Notes

Will allow for setting of the packet level 1-3
1 will send a raw packet
2 will send the packet encapsulated in an ip packet
3 will send the packet encapsulated in TCP (UDP option if I have time)

Lets start with layer 3 and work down


## Scope
IPv4 only
Send packets on top of IP
Values need to be in hex format

## Whats left?
Put everything into a buffer, use memcpy and len of each element.



## Todo
Encapsulate the given packet in an IP datagram and send it to the input IP address

setup a socket to the ipaddress to send to
start with TCP packet

allow option for auto checksum


multithreading maybe







