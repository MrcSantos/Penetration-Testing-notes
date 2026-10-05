### Feroxbuster
#### Ferric Oxide.

A simple, fast, recursive content discovery tool.

Feroxbuster is a tool designed to perform Forced Browsing. Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker.

----------

#### Cheatsheet

```
feroxbuster -u http://<domain>
```

----------

#### Notes

Feroxbuster tries to automatically understand what to do when a website responds with a 200 instead of a 404 or such.
It can't do it if the response always changes in word count, size and such.

----------

#### Resources:

 - https://github.com/epi052/feroxbuster
