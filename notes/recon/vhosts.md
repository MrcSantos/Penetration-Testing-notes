### Virtual Hosts

Virtual hosting is a method for hosting multiple domain names on a single server (or pool of servers).

Virtual hosts enumeration transforms services like http and https into new targets.

----------

This is how to do vhost enumeration with ffuf
```
ffuf -u https://<IP> -H 'Host: FUZZ.<DOMAIN>' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```
ffuf -w subdomains.txt -H "Host: FUZZ.domain" -u https://<domain>
gobuster vhost --wordlist "/path/to/wordlist.txt" --url $URL
wfuzz -H "Host: FUZZ.something.com" --hc 404,403 -c -z file,"/path/to/wordlist.txt" $URL
ffuf -H "Host: FUZZ.$DOMAIN" -c -w "/path/to/wordlist.txt" -u $URL
```
