
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



## Todo
Encapsulate the given packet in an IP datagram and send it to the input IP address
Add error or warning if input value does not fit in length of the attribute

setup a socket to the ipaddress to send to
start with TCP packet


multithreading maybe







