define($IP 192.168.56.105)
define($MAC 00:00:00:00:01:00)

source :: FromDevice
dest :: ToDevice

c :: Classifier(
  23/06,           //This is to match TCP SYN packets
  -);                //Default case

source -> c

c[0] -> GetFeatures -> EtherMirror -> dest;

c[1] -> Discard;
