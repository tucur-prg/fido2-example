# fido2-example

自己証明書作成  

```
openssl genrsa 2048 > private.key
openssl req -new -x509 -days 3650 -key private.key -sha512 -out server.crt
```
