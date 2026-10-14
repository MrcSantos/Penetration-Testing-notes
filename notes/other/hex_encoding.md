### Hex encoding

In order to decode a Hex string you must do this command
```
echo <HEX_STRING> | xxd -r -p
```

example:
```
echo NzU2ZTZjNmY2MzZiMmQzOTY2MzQzNTY0Mzk2MTM2MzIzNjMzMzA= | base64 -d | xxd -r -p
```
