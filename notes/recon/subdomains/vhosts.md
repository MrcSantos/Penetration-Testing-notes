### Virtual Hosts

Virtual hosting is a method for hosting multiple domain names on a single server (or pool of servers).

Virtual hosts enumeration transforms services like http and https into new targets.

----------

This is how to do vhost enumeration with ffuf
```
ffuf -u https://<IP> -H 'Host: FUZZ.<DOMAIN>' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```
