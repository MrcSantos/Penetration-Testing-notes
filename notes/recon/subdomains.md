### Subdomain Enumeration

#### Passive subdomain

Use the tool crt.sh (https://github.com/az7rb/crt.sh) in order to enumerate passively the subdomains

```
crt.sh -d <domain>
```

#### Subdomain bruteforcing
```
dnsx -d <domain> -w inputs/subdomains_wordlist.txt -resp -o tools_output/dnsx
```
