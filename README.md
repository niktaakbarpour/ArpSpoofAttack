# Arp Spoof Attack
A Kotlin project to spoof Arp packets in a local network using "pcap4j" library. 
This program monitors a LAN to discover Arp packets. As an Arp packet is discovered, regardless of its receiver, an ArpReply packet will be unicasted to the sender of the packet. As a result, the sender identifies us as their contact and sends their packets to us.
