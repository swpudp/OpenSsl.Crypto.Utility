# OpenSsl.Crypto.Utility
crypto helper using bc-library

## 1、摘要计算
### MD5
```C#
string content = "123456";
string cipher = DigestUtils.Md5(content, Encoding.UTF8);
//cipher:e10adc3949ba59abbe56e057f20f883e
```
### Sm3
```C#
string content = "123456";
string cipher = DigestUtils.Sm3(content, Encoding.UTF8);
//cipher:207cf410532f92a47dee245ce9b11ff71f578ebd763eb3bbea44ebd043d018fb
```
### Sha1
```C#
string content = "123456";
string cipher = DigestUtils.Sha1(content, Encoding.UTF8);
//cipher:7c4a8d09ca3762af61e59520943dc26494f8941b
```
### Sha224
```C#
string content = "123456";
string cipher = DigestUtils.Sha224(content, Encoding.UTF8);
//cipher:f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6
```
### Sha256
```C#
string content = "123456";
string cipher = DigestUtils.Sha256(content, Encoding.UTF8);
//cipher:8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
```
### Sha384
```C#
string content = "123456";
string cipher = DigestUtils.Sha384(content, Encoding.UTF8);
//cipher:0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454
```
### Sha512
```C#
string content = "123456";
string cipher = DigestUtils.Sha512(content, Encoding.UTF8);
//cipher:ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413
```
### HmacSha1
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacSha1(key, content, Encoding.UTF8);
//cipher:4343ce57bbd76ed06b2f484a39a165bf5cadd0e0
```
### HmacSha224
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacSha224(key, content, Encoding.UTF8);
//cipher:94c99b8ed5ca9967d539b5cc6c7ed669296c0c4b8d8cae0ac99262a5
```
### HmacSha256
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacSha256(key, content, Encoding.UTF8);
//cipher:c642d1feaaa62153d0f3d1fc0cbab4bb9423bc6e456c100459296ab1c45407fd
```
### HmacSha384
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacSha384(key, content, Encoding.UTF8);
//cipher:1758b23e72e118766af1e5de07ede6af12dc4535fd7ce0818a5b90a1ee7f7aa9be0fc62af19444c17bb44ed80743363c
```
### HmacSha512
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacSha512(key, content, Encoding.UTF8);
//cipher:2835d49cc09f389348726ef7360034f572111006efe8fb81e11c9fdef8e9af2f59c9e0270e3d22e2e6d6d6621cbc3663e8f216774be05b881684bc7152931f06
```
### HmacMd5
```C#
string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
string content = "123456";
string cipher = DigestUtils.HmacMd5(key, content, Encoding.UTF8);
//cipher:0b04a6b84cc8d5f16d60b3fd7fd036ab
```

## 数据签名

### RSA签名
```C#
string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
string data = "123456";
//加签（base64）
string sign = SignatureUtils.RsaSignToBase64(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);

//加签（hex）
string sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);

//加签（自定义编码）
byte[] signBytes = SignatureUtils.RsaSignToBytes(Convert.FromBase64String(privateKey), Encoding.UTF8.GetBytes(data), RsaSignerAlgorithm.SHA1withRSA);
string sign = SimpleCoder.EncodeBytes(cipherBytes);

```
### RSA验签
```C# 
string publicKey =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
string data = "123456";
//自定义编码
string sign =    "MjBhNzY2ZTE4ZjdjMzVkMWI3ZTgzMjZlZDU4MTBjNTExODg1OGIxNjc5ODQxZjliMjgxYzNhNTVkOWZmMTFhNDcxMDU3ZGI4Njg1NzllMDAyYTljOWU1ZGJiMDUyZDQ3MTkwM2ViYThhNWUyMmM4ZGQyOTU1ZjBlY2YyZmUwZjYxMTM2M2YyOWIzMjcxMTFlZjFiMGY3NGY2OTAxNGVhZWUyNGI3ZTMwYWUzOTFmNTYwMWYzMTJmMGUwNTNhY2EyNDIyYjkxMjNlY2U5NjJhMTNhYWY2ODQwYjEzZDI3MjQyZWNjYzhiNmYwMjI4MjczNWM1NWVjYWY1NjIyNmQ2Ng==";
byte[] signBytes = SimpleCoder.DecodeBytes(cipher);
bool isSign = SignatureUtils.RsaVerifyFromBytes(Convert.FromBase64String(publicKey), Encoding.UTF8.GetBytes(data),signBytes, RsaSignerAlgorithm.SHA1withRSA);


//base64
string sign = "IKdm4Y98NdG36DJu1YEMURiFixZ5hB+bKBw6Vdn/EaRxBX24aFeeACqcnl27BS1HGQPrqKXiLI3SlV8Ozy/g9hE2PymzJxEe8bD3T2kBTq7iS34wrjkfVgHzEvDgU6yiQiuRI+zpYqE6r2hAsT0nJC7MyLbwIoJzXFXsr1YibWY=";
bool isSign = SignatureUtils.RsaVerifyFromBase64(publicKey, data, sign, RsaSignerAlgorithm.SHA1withRSA);

//hex
string sign =
"20a766e18f7c35d1b7e8326ed5810c5118858b1679841f9b281c3a55d9ff11a471057db868579e002a9c9e5dbb052d471903eba8a5e22c8dd2955f0ecf2fe0f611363f29b327111ef1b0f74f69014eaee24b7e30ae391f5601f312f0e053aca2422b9123ece962a13aaf6840b13d27242eccc8b6f02282735c55ecaf56226d66";
bool isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA1withRSA);

```

### SM2加签
```C#

string privateKey = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
string content = "123456";
//base64
string sign = SignatureUtils.Sm2SignToBase64(privateKey, content);

//hex
string sign = SignatureUtils.Sm2SignToHex(privateKey, content);

//自定义编码
byte[] signBytes = SignatureUtils.Sm2SignToBytes(privateKey, content);
string sign = SimpleCoder.EncodeBytes(signBytes);
```

### SM2验签

```C#

string content = "123456";
string publicKey = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";

//base64
string sign = "MEUCIHa9L0fTR+NfyXzujhyRmCut2yhpgibRY83rRmFO+2MZAiEAi5BEsaQusGBAQR3KVA+XneofYCEHlvHadHn07ljCFjE=";
bool isSuccess = SignatureUtils.Sm2VerifyFromBase64(content, publicKey, sign);

//hex
string sign = "3045022100df46277276b6c5fa8e80b64c13f9c025d19204ad5f6eb474404ccaecfe09a9ef02203036e60e91917b62bd367cb8da3f22da1d353dee32b9b61fad66045fc8fcd9f2";
bool isSuccess = SignatureUtils.Sm2VerifyFromHex(content, publicKey, sign);

//自定义解码
string sign = "MzA0NjAyMjEwMGJjMzEwNjVlMGE0OGY5YzBkYmIxNGY3NWU5ZTQ2ZjkzNTEzY2IwOGZjYTcxMThjMWIzMzI4NzM5NWM0MTE5OTYwMjIxMDBhZWRlNGE5NGU1OTM4MWEwYTBlNDRhZmUzZDU4NjI0ZTYzNGZlNDRmMWU1ZmNhZjMzMThmZDEzOTFjYzhmZGE2";
byte[] signResultBytes = SimpleCoder.DecodeBytes(sign);
bool isSuccess = SignatureUtils.Sm2VerifyFromBytes(content, publicKey, signResultBytes);

```

## 加密/解密

### AES加密
```C#

Encoding encoding = Encoding.UTF8;
string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
string key = secretHex.Substring(0, 16);
string iv = secretHex.Substring(0, 16);
string content = "123456";

//base64
string cipher = CryptoUtils.AesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5, iv);

//hex
string cipher = CryptoUtils.AesEncryptToHex(content, key, CipherMode.CBC, CipherPadding.PKCS5, iv);

//自定义编码
byte[] plainBytes = Encoding.UTF8.GetBytes(content);
byte[] keyBytes = Encoding.UTF8.GetBytes(key);
byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
byte[] cipherBytes = CryptoUtils.AesEncryptToBytes(plainBytes, keyBytes, CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
string cipher = SimpleCoder.EncodeBytes(cipherBytes);

```

### AES解密
```C#

Encoding encoding = Encoding.UTF8;
string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
string key = secretHex.Substring(0, 16);
string iv = secretHex.Substring(16);

//base64密文
string cipher = "BmaC2ZzPufbQKhZJQ+JQwA==";
string plainText = CryptoUtils.AesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5, iv);

//hex密文
string cipher = "066682d99ccfb9f6d02a164943e250c0";
string plainText = CryptoUtils.AesDecryptFromHex(cipher, key, CipherMode.CBC, CipherPadding.PKCS5, iv);

//自定义编码密文
string cipher = "MDY2NjgyZDk5Y2NmYjlmNmQwMmExNjQ5NDNlMjUwYzA=";
byte[] cipherBytes = SimpleCoder.DecodeBytes(cipher);
byte[] keyBytes = Encoding.UTF8.GetBytes(key);
byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
string plainText = CryptoUtils.AesDecryptFromBytes(cipherBytes, keyBytes, CipherMode.CBC, CipherPadding.PKCS5, ivBytes);

```

### DES加密

```C#

```

### DES解密
```C#

```