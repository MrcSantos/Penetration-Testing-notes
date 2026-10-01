### Faraday / Faraday-CLI


```
farafay-cli services list | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[0-9]+' | awk '{print $1 ":" $2}' > services.txt
```
