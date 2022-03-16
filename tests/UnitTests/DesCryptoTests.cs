using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

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
            byte[] ivBytes = encoding.GetBytes(iv);
            string content = "223456";
            byte[] cipherBytes = CryptoUtils.DesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string cipher = Convert.ToBase64String(cipherBytes);
            string expected = "ScyAHlPUH0E=";//结果来自http://www.1818288.com/o/?id=NDI2
            Assert.AreEqual(expected, cipher);
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
            byte[] cipherBytes = CryptoUtils.DesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.DesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
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
            byte[] cipherBytes = CryptoUtils.DesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.DesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5);
            Assert.AreEqual(content, plainText);
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
            var cipher = "Zp3u+AGxLBA=";
            string actual = CryptoUtils.DesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            string expected = "123456";
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        /// 加密测试（Hex）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToHexWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);
            string content = "223456";

            byte[] cipherBytes = CryptoUtils.DesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string cipher = HexUtils.ToHexString(cipherBytes);
            string expected = "49cc801e53d41f41";//结果来自http://www.1818288.com/o/?id=NDI2
            Assert.AreEqual(expected, cipher);
        }


        /// <summary>
        /// 解密测试（Hex）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DecryptFromHexWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            byte[] ivBytes = encoding.GetBytes(iv);

            string cipher = "49cc801e53d41f41";
            string plainText = CryptoUtils.DesDecrypt(key, HexUtils.ToByteArray(cipher), CipherMode.CBC, CipherPadding.PKCS7, ivBytes);

            string expected = "223456";
            Assert.AreEqual(expected, plainText);
        }

        /// <summary>
        /// 加密测试（自定义编码算法）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToSimpleCoderWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);
            string content = "223456";

            byte[] keyBytes = encoding.GetBytes(key);
            byte[] ivBytes = encoding.GetBytes(iv);

            byte[] cipherBytes = CryptoUtils.DesEncrypt(keyBytes, content, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string hexCipher = HexUtils.ToHexString(cipherBytes);
            string webHexCipher = "49cc801e53d41f41";
            Assert.AreEqual(hexCipher, webHexCipher);

            string cipher = SimpleCoder.EncodeBytes(cipherBytes);
            Assert.IsNotNull(cipher);
            //NDljYzgwMWU1M2Q0MWY0MQ==
            System.Console.WriteLine(cipher);
        }

        /// <summary>
        /// 解密测试（自定义解码算法）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DesDecryptFromSimpleCoderWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 24);
            string iv = secretHex.Substring(24);

            string cipher = "NDljYzgwMWU1M2Q0MWY0MQ==";
            byte[] cipherBytes = SimpleCoder.DecodeBytes(cipher);

            byte[] keyBytes = encoding.GetBytes(key);
            byte[] ivBytes = encoding.GetBytes(iv);

            string plainText = CryptoUtils.DesDecrypt(keyBytes, cipherBytes, CipherMode.CBC, CipherPadding.PKCS7, ivBytes);
            string content = "223456";
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// 随机生成密钥加密解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void RandomKeyToEncryptAndDecryptTest()
        {
            Random rd = new Random();
            byte[] buffer = new byte[8];
            rd.NextBytes(buffer);

            byte[] keyBytes = HexUtils.EncodeByteArray(buffer);
            Console.WriteLine("DesEncrypt random key:len->{2},base64->{0},hex->{1}", Convert.ToBase64String(keyBytes), HexUtils.ToHexString(keyBytes), keyBytes.Length);

            byte[] ivBuffer = new byte[4];
            rd.NextBytes(ivBuffer);
            byte[] ivBytes = HexUtils.EncodeByteArray(ivBuffer);
            Console.WriteLine("DesEncrypt random iv:len=>{2},base64->{0},hex->{1}", Convert.ToBase64String(ivBytes), HexUtils.ToHexString(ivBytes), ivBytes.Length);

            string plainText = string.Join("", Enumerable.Range(0, 100).Select(f => Guid.NewGuid()));
            string cipher = HexUtils.ToHexString(CryptoUtils.DesEncrypt(keyBytes, plainText, CipherMode.CBC, CipherPadding.PKCS5, ivBytes));

            string actual = CryptoUtils.DesDecrypt(keyBytes, HexUtils.ToByteArray(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(plainText, actual);
        }
    }
}
