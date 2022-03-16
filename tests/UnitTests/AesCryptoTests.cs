using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// AES加密/解密测试
    /// </summary>
    [TestClass]
    public class AesCryptoTests
    {
        /// <summary>
        /// 加密测试（base64）
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
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string cipher = Convert.ToBase64String(cipherBytes);
            string expected = "BmaC2ZzPufbQKhZJQ+JQwA==";//结果来自yz.jf.bank->SPDBFactor2->CreateEncrypt改写入参后计算
            Assert.AreEqual(expected, cipher);
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
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string cipher = HexUtils.ToHexString(cipherBytes);
            Assert.IsNotNull(cipher);
            Console.WriteLine("EncryptToHex->cipher:" + cipher);
        }

        /// <summary>
        /// 加密测试（自定义编码）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptToBytesWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string content = "123456";
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string cipher = SimpleCoder.EncodeBytes(cipherBytes);

            Assert.IsNotNull(cipher);
            Console.WriteLine("EncryptToBytes->cipher:" + cipher);
        }

        /// <summary>
        /// 解密测试（base64）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DecryptFromBase64WithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string cipher = "BmaC2ZzPufbQKhZJQ+JQwA==";
            string plainText = CryptoUtils.AesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, iv);
            string expected = "123456";
            Assert.AreEqual(expected, plainText);
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
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);
            string cipher = "066682d99ccfb9f6d02a164943e250c0";
            string plainText = CryptoUtils.AesDecrypt(key, HexUtils.ToByteArray(cipher), CipherMode.CBC, CipherPadding.PKCS5, iv);
            string expected = "123456";
            Assert.AreEqual(expected, plainText);
        }

        /// <summary>
        /// 加密测试（自定义编码）
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void DecryptFromBytesWithCBCPKCS5Test()
        {
            Encoding encoding = Encoding.UTF8;
            string secret = "ZWNyOC00MjAhLWFmNjEtMzAhYTYxZDEhMWV2MC42NjP2MjA0NDY3NDU5MjgwLjk4";
            string secretHex = DigestUtils.Md5(DigestUtils.Sha256(secret, encoding), encoding);
            string key = secretHex.Substring(0, 16);
            string iv = secretHex.Substring(16);

            string cipher = "MDY2NjgyZDk5Y2NmYjlmNmQwMmExNjQ5NDNlMjUwYzA=";
            byte[] cipherBytes = SimpleCoder.DecodeBytes(cipher);

            string plainText = CryptoUtils.AesDecrypt(key, cipherBytes, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string expected = "123456";
            Assert.AreEqual(expected, plainText);
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
            Console.WriteLine("key.len->{0},iv len->{1}", encoding.GetBytes(key).Length, encoding.GetBytes(iv).Length);
            string content = "1E529EC7-214C-43CF-99DA-EFDDE450F130";
            string nonce = "ADBC4F5D-EBBC-4DAF-8E38-1A06EE31ECBC";
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.GCM, CipherPadding.NONE, iv, nonce);
            string cipher = Convert.ToBase64String(cipherBytes);
            Console.WriteLine(cipher);
            string plainText = CryptoUtils.AesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.GCM, CipherPadding.NONE, iv, nonce);
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
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5, iv);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.AesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5, iv);
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
            byte[] cipherBytes = CryptoUtils.AesEncrypt(key, content, CipherMode.CBC, CipherPadding.PKCS5);
            string cipher = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.AesDecrypt(key, Convert.FromBase64String(cipher), CipherMode.CBC, CipherPadding.PKCS5);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// 字节数组密钥测试
        /// </summary>
        [TestMethod]
        public void EncryptAndDecryptTestWithBytesKey()
        {
            string valueStr = "{\"request\":{\"body\":{\"ntbusmody\":[],\"ntecocsax1\":[{\"brneac\":\"755936046310201\",\"cstnam\":\"中建电子商务有限责任公司\",\"intacc\":\"755936046310903\",\"intflg\":\"N\",\"ntfurl\":\"http://118.113.15.111:8081/bank/cmb/transaction\",\"rcvchk\":\"Y\",\"shracc\":\"755936046310903\",\"shrnam\":\"银企直连专用测试企业279\",\"yurref\":\"20211126163904SSSSystem.Random\"}]},\"head\":{\"funcode\":\"NTECOCSA\",\"reqid\":\"20211126163904SSSSystem.Random\",\"userid\":\"N002986845\"},\"signature\":{\"sigdat\":\"\",\"sigtim\":\"20211126163904\"}},\"signature\":{\"sigdat\":\"Xvf89tMK65/336cRiuRcYWHU4igzF2jiuvtOUvoBwq8Ztt5HReF8GgOdOXVW6orE/hoqihL7QqUYD2RjnmxSj6lfNR5VOJogdKBE/4sTq+fjgEcZiud82YBaMetozLTyxuwHIYAiIAaO2ZmrPP1Puwfh2fEva7/ySeX182a+FRxhbtN6Xnw7echGAmgtAO0jOCawuaKitP6XV9eb2w1s+T56GGXvVDYtUIx9Y3OE6T0FA6VUR37cBggwofKiXKTR4pSQSW5udw4K361HNPGaTbcaowUTN1hrYSWx6xroplr7LrU5hGwjczTOfGFvPPGQ8Aix3EBgwpY2+rXf+bGDDA==\",\"sigtim\":\"20211126165559\"}}";
            string aesStr = "It0BeoptL9HSWzPuMJ4es2iDgMNQVGVMe2vix+Lz/D7Ykpkqjt9kWHezH/MWxwPNZDS3V3hxNfRd9C6k1kK4v04jwPx2C/Yu2x18ncb2iCTXvJfbJpKq88p0oX4gB1ArGGFT0li7NH3uSUdf4AQYFoPO2O9FDThwVWjHrW5I6a+8W64Ue/3VQsGLFdtT25UDEnLUKiTMnRfdt1Q0eSfB09SpHlrZe7ikLiMAVS/tVMmCJcfcak8f1XlEf87W/aZBfpJuU1TEvvsVCrJZNxs8aOuBY55C1t5kVCA4spSwVi9baJwe9UznaSx2S4HSfgsy2q9HNdfilWsdOv/Bbwd2/joBee4AYsGpVIUp692xLwyXUAV+ZwUiY6/AeeoRMxrL+hC5DxMT5N4QQqNOFBjHZFfRMJ+s7P8Jao7d2Y7iESHQDwE/qKwF9bed75yzOPR3dXXUL7MLD4DBxhpPlHZiwzIhwhVaoYZIhmnjG6HInHFooHE3V2wcx86ssPH9eoLYQoO7Ey1KQeeYGYU54GeidLZhSABDK7CY/oOScnGjIiinG5+mUDlXd+2eqc4W4n8KbvYJDdoh0T2ElQZeJDHi7XLUqLhzen8cPjkz3XFNMRQfG+K7EJuRK47lMvjx8egO1uzVm+vzjO5cCwnyFGjCZJd+1NWVH09U3OCb0y648+ihcKakVHzvvTQoO+fLCaAkPm9O7C7wdvZtmemSsdaGNRMBMiMtcdYkLOuZdVO3HMAcFKrBsTXGtsE/fbsvcWZwqAZAYbhdj97W+edpVliTNRIwue9l0r2W1+gpDemckeUsCTNRJb7OH975XeJaL11eLoFaiFsmTc+1pc9qPyfmrFVcigKxUTzaBDOpGm9Ut+TdXPTF5MYWKN4iz6EiV8UajxKQzWJPA8uQoYRHvlAIoC8z6vEqJUOhXhdQz9tE+hbkN8yz78TkhsGo4TFxL3ID5bfktyrt+n5WlgW+KNcxfKHPNiZsT0l9PrjmLdfaRH49dQtWDVei6irGEfC2SrmB6xS8njpoSHOmivY6eBWBB71cRQQ7xzR+C8d/+DILuj3k52o7ht4uO2179WWCSrAmHX+ai4OdhBP5o1ftfAppwjjj8oi2Iki24PIMuHXQ4qm5+u2HxWzNLAuhRJZiyButfHriBosoAP/6sZPibvWRuGrKVfcIbPMe68Le+z22o/+5bBCKH0ohvSiHvm9mzE1J";

            string aesKey = "YSqdwE8vAQ1BcfYCpESUsnVzOOMA2ZSd";
            byte[] aseBytes = CryptoUtils.AesEncrypt(Convert.FromBase64String(aesKey), valueStr, CipherMode.ECB, CipherPadding.PKCS7);
            string actualAesStr = Convert.ToBase64String(aseBytes);
            Assert.AreEqual(aesStr, actualAesStr);

            string plainText = CryptoUtils.AesDecrypt(Convert.FromBase64String(aesKey), Convert.FromBase64String(actualAesStr), CipherMode.ECB, CipherPadding.PKCS7);
            Assert.AreEqual(valueStr, plainText);
        }

        /// <summary>
        /// 随机生成密钥加密解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void RandomKeyToEncryptAndDecryptTest()
        {
            //16字节 128位
            GetRandomKey(16, out byte[] keyBytes, out byte[] ivBytes);
            RandomKeyToEncryptAndDecrypt(keyBytes, ivBytes);

            //24字节 192位
            GetRandomKey(24, out keyBytes, out ivBytes);
            RandomKeyToEncryptAndDecrypt(keyBytes, ivBytes);

            //32字节 256位
            GetRandomKey(32, out keyBytes, out ivBytes);
            RandomKeyToEncryptAndDecrypt(keyBytes, ivBytes);
        }

        private static void GetRandomKey(int len, out byte[] keyBytes, out byte[] ivBytes)
        {
            Random rd = new Random();
            byte[] buffer = new byte[len / 2];
            rd.NextBytes(buffer);

            //128/192/256
            //16字节/24字节/32字节
            keyBytes = HexUtils.EncodeByteArray(buffer);
            Console.WriteLine("AesEncrypt random {2}字节 key:base64->{0},hex->{1}", Convert.ToBase64String(keyBytes), HexUtils.ToHexString(keyBytes), len);

            byte[] ivBuffer = new byte[8];
            rd.NextBytes(ivBuffer);
            ivBytes = HexUtils.EncodeByteArray(ivBuffer);
            Console.WriteLine("AesEncrypt random {2}字节 iv:base64->{0},hex->{1}", Convert.ToBase64String(ivBytes), HexUtils.ToHexString(ivBytes), len);
        }

        /// <summary>
        /// 随机key加密解密
        /// </summary>
        private static void RandomKeyToEncryptAndDecrypt(byte[] keyBytes, byte[] ivBytes)
        {
            string plainText = string.Join("", Enumerable.Range(0, 100).Select(f => Guid.NewGuid()));
            string cipher = HexUtils.ToHexString(CryptoUtils.AesEncrypt(keyBytes, plainText, CipherMode.CBC, CipherPadding.PKCS5, ivBytes));

            string actual = CryptoUtils.AesDecrypt(keyBytes, HexUtils.ToByteArray(cipher), CipherMode.CBC, CipherPadding.PKCS5, ivBytes);
            Assert.AreEqual(plainText, actual);
        }
    }
}
