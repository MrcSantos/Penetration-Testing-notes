### NMAP
#### The Network Mapper.

Nmap is a network discovery and security auditing tool.

It uses raw IP packets to determine what hosts are available on the network, what services those hosts are offering, what operating systems they are running and dozens of other characteristics.

----------

#### Cheatsheet


Command that covers 90% of use cases:

```
sudo nmap --reason --osscan-limit --max-os-tries 1 -p- -T4 -sV -n --script="default,auth,discovery,safe,vuln,vulners,exploit" -iL targets.txt
```

From gnmap to list of open host:port
```
awk '/^Host: .*Status: Up/ { ip=$2 } /^Host: .*Ports:/ { for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+\/open\/tcp/) { split($i,p,"/"); print ip ":" p[1] } }'
```

----------

#### Notes

Instead of ```-T4``` you can put ```--min-rate 10000```.

```--min-rate 10000``` is a good start for maximum speed, going faster should produce false positives and not detect true positives.

----------

#### Resources:

https://www.geeksforgeeks.org/ethical-hacking/nmap-cheat-sheet/
