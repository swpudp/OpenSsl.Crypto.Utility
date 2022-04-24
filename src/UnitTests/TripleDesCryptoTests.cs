using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// Triple DES加密/解密测试
    /// </summary>
    [TestClass]
    public class TripleDesCryptoTests
    {
        /// <summary>
        /// 加密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBase64WithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            //80ba0e20 a98a2be3 a07c5861 3efcb322
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.TripleDesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string cipher = Convert.ToBase64String(cipherBytes);
            string expected = "F8JGF58EUx0=";//结果来自https://the-x.cn/en-US/cryptography/tripledes.aspx
            Assert.AreEqual(expected, cipher);
        }

        /// <summary>
        /// 加密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBase64WithKeyBytesCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            //80ba0e20 a98a2be3 a07c5861 3efcb322
            string key = secretHex.Substring(0, 24);
            byte[] keyBytes = encoding.GetBytes(key);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.TripleDesEncrypt(keyBytes, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string cipher = Convert.ToBase64String(cipherBytes);
            string expected = "F8JGF58EUx0=";//结果来自https://the-x.cn/en-US/cryptography/tripledes.aspx
            Assert.AreEqual(expected, cipher);
        }

        /// <summary>
        /// 解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DecryptFromBase64WithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            var cipher = "IfZx5s8KvGEXvZgZrXdBLQ==";
            string actual = CryptoUtils.TripleDesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string expected = "42793222";
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        /// 解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DecryptFromBase64WithKeyBytesCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            byte[] keyBytes = encoding.GetBytes(key);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            var cipher = "IfZx5s8KvGEXvZgZrXdBLQ==";
            string actual = CryptoUtils.TripleDesDecrypt(keyBytes, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string expected = "42793222";
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        /// 随机生成密钥加密解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void RandomKeyToEncryptAndDecryptTest()
        {
            Random rd = new Random();
            byte[] buffer = new byte[12];
            rd.NextBytes(buffer);

            byte[] keyBytes = HexUtils.EncodeByteArray(buffer);
            Console.WriteLine("TripleDesEncrypt random key:base64->{0},hex->{1}", Convert.ToBase64String(keyBytes), HexUtils.ToHexString(keyBytes));

            byte[] ivBuffer = new byte[4];
            rd.NextBytes(ivBuffer);
            byte[] ivBytes = HexUtils.EncodeByteArray(ivBuffer);
            Console.WriteLine("TripleDesEncrypt random iv:base64->{0},hex->{1}", Convert.ToBase64String(ivBytes), HexUtils.ToHexString(ivBytes));

            string plainText = string.Join("", Enumerable.Range(0, 100).Select(f => Guid.NewGuid()));
            string cipher = HexUtils.ToHexString(CryptoUtils.TripleDesEncrypt(keyBytes, plainText, CipherMode.CBC, CipherPadding.PKCS5, ivBytes));

            string actual = CryptoUtils.TripleDesDecrypt(keyBytes, HexUtils.ToByteArray(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(plainText, actual);
        }

        /// <summary>
        /// 加密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBase64WithCBCPKCS5SameKeyTest()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.TripleDesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.TripleDesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// 加密（无IV）测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBase64WithoutIVTest()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.TripleDesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.TripleDesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5);
            Assert.AreEqual(content, plainText);
        }
    }
}
