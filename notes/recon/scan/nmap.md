### NMAP
#### The Network Mapper.

Nmap is a network discovery and security auditing tool.

It uses raw IP packets to determine what hosts are available on the network, what services those hosts are offering, what operating systems they are running and dozens of other characteristics.

----------

#### Cheatsheet


Command that covers 90% of use cases:

```
sudo nmap --reason -p- -T4 -sV -n --script="default,auth,discovery,safe,vuln,vulners,exploit" -iL targets.txt
```



----------

#### Notes

----------

#### Resources:

https://www.geeksforgeeks.org/ethical-hacking/nmap-cheat-sheet/
