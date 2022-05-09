
# app-auth の mock

## ID Token のフォーマット

https://jwt.io/

```
{
  "iss": "http://localhost/mock-app-auth/",
  "sub": "1234567890",
  "aud": ["app-auth"],
  "exp": 1652092282,
  "iat": 1516239022,
  "nonce": "x"
}
```

iss が issur の値と違うと弾かれる  
aud が client_id の値が含まれてないと弾かれる  
exp が過去の時間だと「ID Token expired」で弾かれる  
exp が 600 秒を超えている場合は「Issued at time is more than 600 seconds before or after the current time」で弾かれる  
