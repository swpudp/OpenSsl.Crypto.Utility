using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// 摘要计算测试
    /// </summary>
    [TestClass]
    public class DigestUtilsTests
    {
        /// <summary>
        /// md5计算摘要测试
        /// </summary>
        [TestMethod]
        public void Md5Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Md5(content, Encoding.UTF8);
            string expect = "e10adc3949ba59abbe56e057f20f883e";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// md5字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Md5BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Md5(content, Encoding.UTF8);
            string expect = "e10adc3949ba59abbe56e057f20f883e";
            Assert.AreEqual(expect, cipher);
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            byte[] md5Bytes = DigestUtils.Md5(contentBytes);
            Assert.AreEqual(cipher, HexUtils.ToHexString(md5Bytes));
        }

        /// <summary>
        /// sm3计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sm3Test()
        {
            string content = "123456";
            byte[] data = Encoding.UTF8.GetBytes(content);
            string sm3 = HexUtils.ToHexString(DigestUtils.Sm3(data, false));
            //使用gmssl验证
            //http://gmssl.org/docs/quickstart.html
            //执行命令 echo -n 123456 | gmssl dgst -sm3
            string expect = "207cf410532f92a47dee245ce9b11ff71f578ebd763eb3bbea44ebd043d018fb";
            Assert.AreEqual(expect, sm3);
        }

        /// <summary>
        /// sm3字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sm3BytesTest()
        {
            string content = "123456";
            string sm3 = DigestUtils.Sm3(content, Encoding.UTF8);
            //使用gmssl验证
            //http://gmssl.org/docs/quickstart.html
            //执行命令 echo -n 123456 | gmssl dgst -sm3
            string expect = "207cf410532f92a47dee245ce9b11ff71f578ebd763eb3bbea44ebd043d018fb";
            Assert.AreEqual(expect, sm3);
        }

        /// <summary>
        /// Sha1计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha1Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha1(content, Encoding.UTF8);
            string expect = "7c4a8d09ca3762af61e59520943dc26494f8941b";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// sha1字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha1BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha1(content, Encoding.UTF8);
            string expect = "7c4a8d09ca3762af61e59520943dc26494f8941b";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha224计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha224Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha224(content, Encoding.UTF8);
            string expect = "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha224字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha224BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha224(content, Encoding.UTF8);
            string expect = "f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha256计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha256Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha256(content, Encoding.UTF8);
            string expect = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha256字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha256BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha256(content, Encoding.UTF8);
            string expect = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha384计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha384Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha384(content, Encoding.UTF8);
            string expect = "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha384字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha384BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha384(content, Encoding.UTF8);
            string expect = "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha512计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha512Test()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha512(content, Encoding.UTF8);
            string expect = "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// Sha512字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void Sha512BytesTest()
        {
            string content = "123456";
            string cipher = DigestUtils.Sha512(content, Encoding.UTF8);
            string expect = "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha1计算摘要测试
        /// </summary>
        [TestMethod]
        public void HmacSha1Test()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            string cipher = DigestUtils.HmacSha1(key, content, Encoding.UTF8);
            string expect = "4343ce57bbd76ed06b2f484a39a165bf5cadd0e0";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha224计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha224Test()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            string cipher = DigestUtils.HmacSha224(key, content, Encoding.UTF8);
            string expect = "94c99b8ed5ca9967d539b5cc6c7ed669296c0c4b8d8cae0ac99262a5";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha256计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha256Test()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            string cipher = DigestUtils.HmacSha256(key, content, Encoding.UTF8);
            string expect = "c642d1feaaa62153d0f3d1fc0cbab4bb9423bc6e456c100459296ab1c45407fd";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha384计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha384Test()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            string cipher = DigestUtils.HmacSha384(key, content, Encoding.UTF8);
            string expect = "1758b23e72e118766af1e5de07ede6af12dc4535fd7ce0818a5b90a1ee7f7aa9be0fc62af19444c17bb44ed80743363c";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha512计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha512Test()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            string cipher = DigestUtils.HmacSha512(key, content, Encoding.UTF8);
            string expect = "2835d49cc09f389348726ef7360034f572111006efe8fb81e11c9fdef8e9af2f59c9e0270e3d22e2e6d6d6621cbc3663e8f216774be05b881684bc7152931f06";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// md5 Hmac计算摘要测试
        /// </summary>
        [TestMethod]
        public void HmacMd5Test()
        {
            string content = "123456";
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string cipher = DigestUtils.HmacMd5(key, content, Encoding.UTF8);
            string expect = "0b04a6b84cc8d5f16d60b3fd7fd036ab";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha1字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HmacSha1BytesTest()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacSha1(key, contentBytes, Encoding.UTF8);
            string expect = "4343ce57bbd76ed06b2f484a39a165bf5cadd0e0";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha224字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha224BytesTest()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacSha224(key, contentBytes, Encoding.UTF8);
            string expect = "94c99b8ed5ca9967d539b5cc6c7ed669296c0c4b8d8cae0ac99262a5";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha256字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha256BytesTest()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacSha256(key, contentBytes, Encoding.UTF8);
            string expect = "c642d1feaaa62153d0f3d1fc0cbab4bb9423bc6e456c100459296ab1c45407fd";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha384字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha384BytesTest()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacSha384(key, contentBytes, Encoding.UTF8);
            string expect = "1758b23e72e118766af1e5de07ede6af12dc4535fd7ce0818a5b90a1ee7f7aa9be0fc62af19444c17bb44ed80743363c";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// HMacSha512字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HMacSha512BytesTest()
        {
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            string content = "123456";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacSha512(key, contentBytes, Encoding.UTF8);
            string expect = "2835d49cc09f389348726ef7360034f572111006efe8fb81e11c9fdef8e9af2f59c9e0270e3d22e2e6d6d6621cbc3663e8f216774be05b881684bc7152931f06";
            Assert.AreEqual(expect, cipher);
        }

        /// <summary>
        /// md5 Hmac 字节数组计算摘要测试
        /// </summary>
        [TestMethod]
        public void HmacMd5BytesTest()
        {
            string content = "123456";
            string key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            string cipher = DigestUtils.HmacMd5(key, contentBytes, Encoding.UTF8);
            string expect = "0b04a6b84cc8d5f16d60b3fd7fd036ab";
            Assert.AreEqual(expect, cipher);
        }
    }
}