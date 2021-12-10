using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;
using System;
using System.Text;

namespace UnitTests
{
    /// <summary>
    /// DES加密/解密测试
    /// </summary>
    [TestClass]
    public class DesCryptoTests
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
            //80ba0e20a98a2be3a07c5861 3efcb322
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            string content = "223456";
            string cipher = CryptoUtils.DesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS7, iv);
            string expected = "ScyAHlPUH0E=";//结果来自http://www.1818288.com/o/?id=NDI2
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
            var cipher = "Zp3u+AGxLBA=";
            string actual = CryptoUtils.DesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string expected = "123456";
            Assert.AreEqual(expected, actual);
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
            string content = "123456";
            string cipher = CryptoUtils.DesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string plainText = CryptoUtils.DesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5, iv);
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
            string cipher = CryptoUtils.DesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5);
            string plainText = CryptoUtils.DesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5);
            Assert.AreEqual(content, plainText);
        }
    }
}
