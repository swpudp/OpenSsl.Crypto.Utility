using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// 国密加密/解密测试
    /// </summary>
    [TestClass]
    public class SmCryptoTests
    {
        /// <summary>
        /// 加密解密测试 - EcbPkcs1Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs1PaddingWithStringTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5((secret), Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            //byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, (content), Encoding.UTF8, CipherMode.CBC, CipherPadding.PKCS1, iv);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, cipherBytes, Encoding.UTF8, CipherMode.CBC, CipherPadding.PKCS1, iv);
            Assert.AreEqual(content, (plain));
        }

        /// <summary>
        /// 加密解密测试 - EcbPkcs1Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs1PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            byte[] data = Encoding.UTF8.GetBytes(content);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, data, CipherMode.ECB, CipherPadding.PKCS1);
            //hex
            string sm4Cipher = HexUtils.ToHexString(cipherBytes);
            Console.WriteLine(sm4Cipher);
            Console.WriteLine(sm4Cipher.Length);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4Cipher), CipherMode.ECB, CipherPadding.PKCS1);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试 - EcbPkcs5Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs5PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.ECB, CipherPadding.PKCS5);
            string sm4Cipher = HexUtils.ToHexString(cipherBytes);
            Console.WriteLine(sm4Cipher);
            Console.WriteLine(sm4Cipher.Length);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4Cipher), CipherMode.ECB, CipherPadding.PKCS5);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试 - EcbPkcs7Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs7PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.ECB, CipherPadding.PKCS7);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.ECB, CipherPadding.PKCS7);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试-EcbNoPadding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbNoPaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "1234567812345678";
            Assert.AreEqual(0, Encoding.UTF8.GetBytes(content).Length % 16);
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.ECB, CipherPadding.NONE);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.ECB, CipherPadding.NONE);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs1Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs1PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.CBC, CipherPadding.PKCS1, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS1, ivBytes);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs5Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs5PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs7Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs7PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 加密解密测试-CbcNoPadding      
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcNoPaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "1234567812345678";

            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.CBC, CipherPadding.NONE, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);

            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.NONE, ivBytes);
            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));

            string keyHex = HexUtils.ToHexString(key);
            string plain1 = CryptoUtils.Sm4Decrypt(keyHex, cipherBytes, Encoding.UTF8, CipherMode.CBC, CipherPadding.NONE, iv);
            Assert.AreEqual(Encoding.UTF8.GetString(plain), plain1);
        }

        /// <summary>
        /// 加密解密测试-CbcNoPadding-自定义解码方法
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcNoPaddingSimpleCoderTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "1234567812345678";

            byte[] key = DigestUtils.Md5(Encoding.UTF8.GetBytes(secret));
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, Encoding.UTF8.GetBytes(content), CipherMode.CBC, CipherPadding.NONE, ivBytes);
            string cipher = HexUtils.ToHexString(cipherBytes);

            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] cihperDecodeBytes = HexUtils.ToByteArray(cipher);
            byte[] plain = CryptoUtils.Sm4Decrypt(key, cihperDecodeBytes, CipherMode.CBC, CipherPadding.NONE, ivBytes);

            Assert.AreEqual(content, Encoding.UTF8.GetString(plain));
        }

        /// <summary>
        /// 生成密钥对测试-压缩公钥
        /// </summary>
        [TestMethod]
        public void GenerateKeyPairCompressedPubKeyTest()
        {
            var keyPair = SmCertUtils.GenerateKeyPair();
            Console.WriteLine("sm2 Private:" + keyPair.Private);
            Console.WriteLine("sm2 Public:" + keyPair.Public);
            Assert.AreEqual(true, keyPair.Public.StartsWith("02") || keyPair.Public.StartsWith("03"));
            KeyPairVerify(keyPair);
        }

        /// <summary>
        /// 生成密钥对测试-未压缩公钥
        /// </summary>
        [TestMethod]
        public void GenerateKeyPairNoCompressedPubKeyTest()
        {
            var keyPair = SmCertUtils.GenerateKeyPair(false);
            Console.WriteLine("sm2 Private:" + keyPair.Private);
            Console.WriteLine("sm2 Public:" + keyPair.Public);
            Assert.AreEqual(true, keyPair.Public.StartsWith("04"));
            KeyPairVerify(keyPair);
        }

        /// <summary>
        /// 密钥对验证
        /// </summary>
        /// <param name="cipherKeyPair"></param>
        private static void KeyPairVerify(CipherKeyPair cipherKeyPair)
        {
            byte[] content = Guid.NewGuid().ToByteArray();
            byte[] privateKey = HexUtils.ToByteArray(cipherKeyPair.Private);
            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content, false, false);
            string sign = HexUtils.ToHexString(signBytes);
            Console.WriteLine("KeyPairVerify->sign：" + sign);

            byte[] publicKey = HexUtils.ToByteArray(cipherKeyPair.Public);
            bool isSuccess = SignatureUtils.Sm2Verify(publicKey, content, HexUtils.ToByteArray(sign), false, false);
            Assert.AreEqual(true, isSuccess);
        }
    }
}