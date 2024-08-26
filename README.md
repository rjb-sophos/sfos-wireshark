# sfos-wireshark
Scripts to dissect SFOS packets in a packet capture using Wireshark

This lua script can be added to a Wireshark installation by dropping it into the appropriate directory - see notes in the .lua file.
The dissector currently focuses on identifying an interpreting packets sent on the network by the following features:
- SATC - Used to provide user identity for TCP connections from a multi-user Windows system. Packets are sent by Server Protection (or, in the past, the SATC client) to the Firewall and responses sent back.
- STAS - Used to assign user identity to IP addresses based on Windows logins monitored via Domain Controller logs and/or WMI queries directly to devices. Packets are exchanged between STAS agents running on Windows Servers and your Firewalls.
