### FFUF
#### Fuzz Faster U Fool.

FFUF is a web fuzzer.

Fuzzing or fuzz testing is an automated software testing technique that involves providing valid, invalid, unexpected, or random data as inputs to a computer program.

----------

#### Cheatsheet

Subdomain enumeration:
```
ffuf -u http://<IP> -H 'Host: FUZZ.<DOMAIN>' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

----------

#### Notes

```-ac``` stands for automatic calibration, it attempts to determine what a nonexistent response looks like and filters similar responses.

```-fs``` stands for filter by size (in byte) (eg. ```-fs 5000``` filters out 5000 bytes responses)

```-fw``` stands for filter by word count (eg. ```-fw 50``` filters out responses with 50 words)

```-fc``` stands for filter by http status code (eg. ```-fc 500``` filters out responses with http status 500 Internal Server Error)

----------

#### Resources:

https://www.geeksforgeeks.org/ethical-hacking/nmap-cheat-sheet/
