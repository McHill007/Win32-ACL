# Win32-ACL
 ACL Wrapper

```perl
use Win32::ACL;
use Data::Dumper; 

my $object = new Win32::ACL();  

my @sacls = $object->getSACL("C:\\Temp");
print Dumper(@sacls);
my @dacls = $object->getDACL("C:\\Temp");
print Dumper(@dacls);
```
