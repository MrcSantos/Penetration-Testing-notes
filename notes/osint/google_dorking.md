Exposed public documents
```
site:<DOMAIN> ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
```

Dir listing vulns
```
site:<DOMAIN> intitle:index.of
```

DB files exposed
```
site:<DOMAIN> ext:sql | ext:dbf | ext:mdb
```

Log file 
```
site:<DOMAIN> ext:log
```

Backup file
```
site:<DOMAIN> ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
```

Login pages
```
site:<DOMAIN> inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth
```

Sql errors
```
site:<DOMAIN> intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
```

Php errors
```
site:<DOMAIN> "PHP Parse error" | "PHP Warning" | "PHP Error"
```

Php info
```
site:<DOMAIN> ext:php intitle:phpinfo "published by the PHP Group"
```

Pastebin 
```
site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com "<DOMAIN>"
```

Github
```
site:github.com | site:gitlab.com "<DOMAIN>"
```

Stackoverflow
```
site:stackoverflow.com "<DOMAIN>"
```

Singup pages
```
site:<DOMAIN> inurl:signup | inurl:register | intitle:Signup
```

Subdomains
```
site:*.<DOMAIN>
```

Sub-subdomains
```
site:*.*.<DOMAIN>
```

Wayback machine
```
Wayback Machine (<DOMAIN>)
```

Show IP addresses
```
(<DOMAIN>) (site:*.*.29.* |site:*.*.28.* |site:*.*.27.* |site:*.*.26.* |site:*.*.25.* |site:*.*.24.* |site:*.*.23.* |site:*.*.22.* |site:*.*.21.* |site:*.*.20.* |site:*.*.19.* |site:*.*.18.* |site:*.*.17.* |site:*.*.16.* |site:*.*.15.* |site:*.*.14.* |site:*.*.13.* |site:*.*.12.* |site:*.*.11.* |site:*.*.10.* |site:*.*.9.* |site:*.*.8.* |site:*.*.7.* |site:*.*.6.* |site:*.*.5.* |site:*.*.4.* |site:*.*.3.* |site:*.*.2.* |site:*.*.1.* |site:*.*.0.*)
```
