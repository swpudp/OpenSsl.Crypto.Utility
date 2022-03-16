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
        public void Sm4EncryptDecryptEcbPkcs1PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.ECB, CipherPadding.PKCS1);
            //hex
            string sm4Cipher = HexUtils.ToHexString(cipherBytes);
            Console.WriteLine(sm4Cipher);
            Console.WriteLine(sm4Cipher.Length);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4Cipher), CipherMode.ECB, CipherPadding.PKCS1);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试 - EcbPkcs5Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs5PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.ECB, CipherPadding.PKCS5);
            string sm4Cipher = HexUtils.ToHexString(cipherBytes);
            Console.WriteLine(sm4Cipher);
            Console.WriteLine(sm4Cipher.Length);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4Cipher), CipherMode.ECB, CipherPadding.PKCS5);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试 - EcbPkcs7Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptEcbPkcs7PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.ECB, CipherPadding.PKCS7);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.ECB, CipherPadding.PKCS7);
            Assert.AreEqual(content, plain);
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
            string key = DigestUtils.Md5(secret, Encoding.UTF8);

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.ECB, CipherPadding.NONE);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.ECB, CipherPadding.NONE);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs1Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs1PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.CBC, CipherPadding.PKCS1, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS1, ivBytes);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs5Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs5PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试-CbcPkcs7Padding
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcPkcs7PaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "123456";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试-CbcNoPadding      
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcNoPaddingTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "1234567812345678";

            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.CBC, CipherPadding.NONE, ivBytes);
            string sm4 = HexUtils.ToHexString(cipherBytes);

            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, HexUtils.ToByteArray(sm4), CipherMode.CBC, CipherPadding.NONE, ivBytes);
            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密解密测试-CbcNoPadding-自定义解码方法
        /// </summary>
        [TestMethod]
        public void Sm4EncryptDecryptCbcNoPaddingSimpleCoderTest()
        {
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string content = "1234567812345678";

            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            //使用NoPadding模式，需要保证字符串长度是16的倍数
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.CBC, CipherPadding.NONE, ivBytes);
            string cipher = SimpleCoder.EncodeBytes(cipherBytes);

            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            byte[] cihperDecodeBytes = SimpleCoder.DecodeBytes(cipher);
            string plain = CryptoUtils.Sm4Decrypt(key, cihperDecodeBytes, CipherMode.CBC, CipherPadding.NONE, ivBytes);

            Assert.AreEqual(content, plain);
        }

        /// <summary>
        /// 加密测试-自定义编码方法
        /// </summary>
        [TestMethod]
        public void Sm4EncryptSimpleCoderTest()
        {
            string secret = "00827f1b4065725790d22f1dfcdf2c220b607ab07a1aa41e62db3bf613a0fba6fb";
            string content = "1234567812345678";
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, CipherMode.ECB, CipherPadding.PKCS7);
            string cipher = SimpleCoder.EncodeBytes(cipherBytes);
            Console.WriteLine(cipher);
            Assert.IsNotNull(cipher);
        }

        /// <summary>
        /// 解密测试-自定义解码方法
        /// </summary>
        [TestMethod]
        public void Sm4DecryptSimpleCoderTest()
        {
            string secret = "00827f1b4065725790d22f1dfcdf2c220b607ab07a1aa41e62db3bf613a0fba6fb";
            string content = "1234567812345678";
            string cipcher = "OWZjNzM0ZGE3ZmRjOGU1YTc3ZjAyMGQ1NDEzZjZhNDYzMTAwMjlmY2FmOThhOTFlMmQwM2QwYjY3OTM3ZmY3MA==";
            byte[] cipherBytes = SimpleCoder.DecodeBytes(cipcher);
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string plainText = CryptoUtils.Sm4Decrypt(key, cipherBytes, CipherMode.ECB, CipherPadding.PKCS7);
            Assert.AreEqual(content, plainText);
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
            string content = Guid.NewGuid().ToString();
            byte[] signBytes = SignatureUtils.Sm2Sign(cipherKeyPair.Private, content);
            string sign = HexUtils.ToHexString(signBytes);
            Console.WriteLine("KeyPairVerify->sign：" + sign);
            bool isSuccess = SignatureUtils.Sm2Verify(cipherKeyPair.Public, content, HexUtils.ToByteArray(sign));
            Assert.AreEqual(true, isSuccess);
        }
    }
}