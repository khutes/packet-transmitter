# Formatting for specfiles


```
<max header size>
attribute-name attribute-length attribute-value
variable-len-attr-name -1 child1-val-len child1-val child2-val-len child2-val
<optional DATA>
```

Line 1 will contain the maxheader size in bytes
Each attribute line will follow the above format. If it is an attribute of variable length the attribue-length variable will be `-1`. This will be followed by pairs. The first value being the lenght


### Special Attributes
An attribute name preceded by a `$` character denotes the checksum
If auto checksum calculation is enabled the value of this attribute will be autocalclated using the tcp/ip checksum algorithm.




