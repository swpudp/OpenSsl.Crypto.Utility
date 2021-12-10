using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;
using System;
using System.Text;

namespace UnitTests
{
    /// <summary>
    /// AES加密/解密测试
    /// </summary>
    [TestClass]
    public class AesCryptoTests
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
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string content = "123456";
            string cipher = CryptoUtils.AesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5, iv, null);
            string expected = "BmaC2ZzPufbQKhZJQ+JQwA==";//结果来自yz.jf.bank->SPDBFactor2->CreateEncrypt改写入参后计算
            Assert.AreEqual(expected, cipher);
        }

        /// <summary>
        /// 加密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBase64WithGCMPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            Console.WriteLine(secretHex);
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string content = "1E529EC7-214C-43CF-99DA-EFDDE450F130";
            string nonce = "ADBC4F5D-EBBC-4DAF-8E38-1A06EE31ECBC";
            string cipher = CryptoUtils.AesEncryptToBase64(content, key, CipherMode.GCM, CipherPadding.NONE, iv, nonce);
            Console.WriteLine(cipher);
            string plainText = CryptoUtils.AesDecryptFromBase64(cipher, key, CipherMode.GCM, CipherPadding.NONE, iv, nonce);
            Assert.AreEqual(content, plainText);
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
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(0, 16);
            string content = "123456";
            string cipher = CryptoUtils.AesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string plainText = CryptoUtils.AesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5, iv);
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
            string key = secretHex.Substring(0, 16);
            string content = "123456";
            string cipher = CryptoUtils.AesEncryptToBase64(content, key, CipherMode.CBC, CipherPadding.PKCS5);
            string plainText = CryptoUtils.AesDecryptFromBase64(cipher, key, CipherMode.CBC, CipherPadding.PKCS5);
            Assert.AreEqual(content, plainText);
        }
    }
}
