using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using OpenSsl.Crypto.Utility;
using Org.BouncyCastle.Security;

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
            string key = DigestUtils.Md5(secret, Encoding.UTF8);
            string iv = "0123456789ABCDEF";
            //byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] cipherBytes = CryptoUtils.Sm4Encrypt(key, content, Encoding.UTF8, CipherMode.CBC, CipherPadding.PKCS1, iv);
            //echo -n 123456 | gmssl sms4-ecb -e -k 9930689b38bd8fe5f0a112d58428696d | base64
            //echo U2FsdGVkX195IULDIwWrYnPR6v3UH7kU5kLp+rgqqBc= | base64 -d | gmssl sms4-ecb -d -k 9930689b38bd8fe5f0a112d58428696d
            string plain = CryptoUtils.Sm4Decrypt(key, cipherBytes, Encoding.UTF8, CipherMode.CBC, CipherPadding.PKCS1, iv);
            Assert.AreEqual(content, plain);
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
            CipherKeyPair? keyPair = SmCertUtils.GenerateKeyPair();
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
            CipherKeyPair? keyPair = SmCertUtils.GenerateKeyPair(false);
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
            Console.WriteLine("privateKey Base64：" + Convert.ToBase64String(privateKey));
            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content);
            string sign = HexUtils.ToHexString(signBytes);
            Console.WriteLine("KeyPairVerify->sign：" + sign);

            byte[] publicKey = HexUtils.ToByteArray(cipherKeyPair.Public);
            Console.WriteLine("publicKey Base64：" + Convert.ToBase64String(publicKey));
            bool isSuccess = SignatureUtils.Sm2Verify(publicKey, content, HexUtils.ToByteArray(sign));
            Assert.AreEqual(true, isSuccess);
        }

        /// <summary>
        /// sm2加密测试
        /// </summary>
        [TestMethod]
        public void Sm2EncryptTest()
        {
            string raw = "[\"v-5KdgUSPNl_cw\",-1764757154,[\"uO64faOeeMEVtt\",[true,-1370426824,-2096822451,\"fIZ3KdzPpXMALrN_N\",\"9B\",\"KZKs\",-441963634,\"hMhE8KpbX\",\"rO4y\",\"6vKWvt44KAs\",1337908602,false,true,821210533,1624511981.0194485,-671244017.711373,-2106321917,\"KgT7dW5cwymxNTEgdr2\",1800056202.7333639,-2097164923.1361678,-280448466.5636127,false,\"BZg5rRAOPCVURvVhS\",false,\"tKXiuDvsoiFQUFg\",\"yMjm\",\"9\",true],\"KOIbWUQDS_mDn\",2026665656.225983,\"TbMF4d51AKLeitwE\",-2047609738,[-617181167.5446944,-1083720362,false,\"XOr07KfKDiVJVgKWtov\",\"Yxz6\",true,false,148664418.4105615,true,449485307,\"qm\",\"4TM_SX8\",1200801715.9050407,-977839230,true,-1243870790.107537,false,true],{\"ikvydmbhfjc\":\"fobD\",\"qimcmjlwvsn\":326794136,\"mmxyhvaafjqg\":77673240.98444043,\"nfvxcfpysmd\":false},-1093178301,\"Zt0lVTqVOE\",\"HYMkBhVs\",{\"pznqvafmibr\":false,\"rmlahwmoj\":-12844976.235485591,\"ghjxe\":\"x4e1XXoqctiY\"},false,-1003994150,752246092.6254109,[true,\"yvwcczCktsd\",false,\"MyXS3\",-359650773.6826117,\"tWY3SJXBA9GGL9Ktegp2\",-377369113,\"IeEGgbht3Odk3G\",false,1439104433.0552194,198749149,1726535599.6054788,true,243438647.76350257,\"MJCZTT1\",\"erbSm_3H\",\"Vedd6rgDJIOBSh\",false,true,false,\"s2Wa1zksFaxcB8\",-1894976891.6270707,false,1580255759,true,true,\"kZsMx-Bw3HzltplJ9k3K\",-635695011.3740687,\"ZSTe\",213615179.60405657],[\"90qJJt3cNZp2\",1357648851.2464657,\"t5T_OvvyI0jaEKDRqHu\",false,false,\"56dY\",\"fMk86QP0P6OICKm_C\",2099533596,-2073073653,\"7\",1732335834.3780026,1198855458,\"67xWf6VGYpebVQ_ePDcZ\",613984615.9920295,false],false,-1333058979,[-1005481770,1347764639.3596714,true,\"qDX-EThcQy3JFzjQzC\",true,529981363,-2078766853.8981714,1985451146.64788,false,true,false,true,false],-1428858010],[[-1198610121,-320583668.27978325,true,true,\"87GSE0Xdc\",402744153.0439735,true,-14322784,false,\"R\",true],[true,true,\"IqkzrDroG_UbVc\",false,-1344755953,700569082,\"UTWngldmLT\",\"oNM3\",false,-2010740057.5860417,1017607843],-252102316.6763822,-2085022943,[1233233747,\"K7NVl8Ls0J4E3MC_j\",true,true,\"ZEWEskDXMEuqYYvWhI\",-1736985514,190313967,\"L7VF-Bcf26inokaJtB\",false,\"MC6hhwdDBAJu_L\",586789683.4014832,true,1238155860,true],{\"bxqdkfetvsfj\":\"S705Gt0qOnIg1v\",\"wbompunt\":true,\"fxlfqxia\":\"I4aeTE24y\",\"fuwihxbff\":-1263804638,\"fngmlfgvfq\":-582474113.0461118,\"jyusxsg\":-2121310660,\"jaztf\":\"gCUba\",\"ucltodme\":\"w5lLoJ4kFuF4JIcQX\",\"yhpokg\":\"EmoCyvqYu_B6BRGUP7S\",\"coyrvqp\":false,\"chfekjnwvywx\":173177047,\"kmuxydsuja\":false,\"ptgusuemg\":\"cTg1WF-7p0YUk\",\"ibnwfdt\":false,\"fkqveqvvzjzh\":false,\"kdglxai\":true,\"ccxfvxviwwrf\":1558365561,\"medaij\":false,\"patot\":-1100330169,\"jzgiiusf\":true,\"lcdtvdibcogt\":\"Zj6dDlER5zSZq_Ol\",\"fyrpxr\":false,\"cjznugkwif\":false,\"wuamb\":\"qZpT73ZCeoy8\",\"pwcvi\":false,\"hbeiooqzq\":\"X9A_hnRTQ0-9oPvKK5x\",\"yfzlzuozesf\":\"BfkkpRtaV_u\",\"mnedisusb\":\"NIxUaE6Q73VgY1EWc\"},[1970507618,-1655491931.2655318,\"Md\",\"jIrVO2FU5\",\"20BvPJMd54g2nsdd\",false,\"OmCliVIPYsvDfMOmt3\",\"XL8f\",false,false,-282375771,\"l5WfQPnI9Z8CFFjd1N\",\"iZk_qS4Oon\",-1365712640.4497643,\"wn2\",292510755.9762621,true],true,\"ZHl0-WIkxlz\",false,1271734666.5633485,-1818633579.5436857,\"hbgbmuokeoL2WDnCr\",true,\"TWktSK31Tbuv5nmvpS32\",[true,-989836752.2722604,843069515.4034109,\"gO7oGii-7tAWR7SM20-\",false,\"009m\",-1553147177.5662124,\"JApIiNZrLHx9QOs\",-834581595,-261077743.89038956,false,2107128235.293607,\"DOJk\",true,\"z0ZuTMS3q\",\"8dt8Yn8wSQ_ZC\",\"LZS2YEupV\",-2062708887,\"P3u\",\"NEXoSdfqg7lM\",false],[-1307094464,\"wGaaFT20HpUSk3WT7\",\"HPXcPtse2_scg8ij\",\"vkCQzoVIWD8G8zI12NP3\",true,\"Q8wtDh\",true,false,\"S\",false,-1998414529,-824560850.8552693],[true,false,\"HWkFZgvm4xxoH0u\",\"DtIw51Um-Z9\",-417961341,1993316409,2103835468,false,148112556,true,2065910228.0226529,false,\"fNkSbo\",true,-1546014497.5263667,-430185108.32487744,false,true,true,\"aLtfzEeirKM\"],[false,-817200222,true,\"7dpJ\",false,\"z2s\",-1093012659,\"qEYV3FGMI\",\"6vzVrA71VTih1by1\",-1589407923,\"QxtTqsWJij\",false,false,true,742862743,1851615642.0069096,\"7JVnxS\",-1199321709.101257,-1295983627.8123832,true,false,true,-1469811683,403756135.83171314,true,\"dUeVOYlhWyH0W\",false,\"6DHmbx_1-rAUcD4\",\"OTZrQUrSOmid1hktjIN0\",-1099792913.0482414],false,true,-1630281339.026131,{\"ousone\":true,\"rtczdyyzyou\":\"gNZxAtL2w8Kd\",\"ofzuhluf\":\"_I_RZ\",\"unbocpufuhj\":false},[false,true,\"-0uKjuOCbFj\",true,false],\"AyOmWE-Y6Fp20WKLaV0F\",699876881.5835302,\"Sp-S\",\"qz\",579751025.0959325],false,[{\"fkuuj\":\"0V1gZ\",\"shosxzbqoq\":true,\"ziopcx\":267857292,\"umywywlgqu\":-1966331368,\"olvcjngqpx\":\"T_CooRzzm\",\"fchvotoejcb\":1058726943.6775169,\"ujqys\":\"KA4jTQPi\",\"iltglztxoiub\":-1539456940,\"xpetotnzg\":true,\"ztejfakm\":true,\"dazxyjmjg\":591929083,\"wsirqlw\":true,\"drewnqn\":-1848025790,\"cowgv\":false,\"wpnkiw\":\"-ULbx7LpmZ\",\"efkpbqxnq\":false},false,true,false,\"QMuKxXhoOwA\",[1709304315.8488638,1564627795,\"hL1rSGX\",\"vAJ80l7SltU6MN4\",431368073,false,-638520058.0081397,-40364105],true,false,{\"hgpxdqyj\":\"QBoPe-OmL2J7LAVY\",\"wmxthjrxzl\":\"w\"},1295115321,728659360,\"0p\",[true,\"LMED-hUsRkxe5\",true,\"E5NR\",-376349890.8101462,true,1144452222,\"fu6RQk_Q1M\",\"rAJ1\",\"dke5HgjSf3GHjG6LpA\",810866264.0968363,false,\"_qK1cXmu2suDionhfZx\",-475965000,-1751184416.9716263,\"CU\",true,false,true,2091844801.019238,\"Gx0IZC6ewEOzxwjAK1\",\"T0aykeFE\",-1564262710.4261444,true,\"iv-rvhYZjD8p2nwigPG\",false,true,\"7DhD\",\"bAzDWvljV\",\"8yy83Y\"],{\"wvefpw\":false,\"cyobdblhbju\":true,\"ahppvvg\":true,\"misaapmzczd\":true,\"zvkzrz\":false,\"gxtkggl\":1527791526.6306558,\"slhpe\":594178765,\"ujsfzlezy\":\"1w779K6OoY9ZNq_RAE\",\"agwrgzefjq\":-1528646077,\"rghbbira\":\"EkDcqOq8\",\"kvgsedo\":-1860258133.8328454,\"hqierqfbtvo\":-521407108.0966379,\"kxpqzmln\":-1543224798,\"byngadkw\":-276704825,\"xbsglgcbq\":83537999.80896756,\"xsaokv\":197372195.47562918,\"irctf\":1048399282},\"4SEQjzmN\",true,true,-1490754125.8058126,{\"elltgvcnlzd\":-369936626.26740205,\"gqkmnjlw\":\"Juk0n1\",\"hyxzg\":-1905901594.0521307,\"qslno\":false,\"lxssketyfu\":43269789,\"naervd\":true,\"cgcpearz\":317725833},{\"zxmbtsr\":\"Tk0qyalT6xYD\",\"pefejcy\":1333894699,\"ewpvbd\":false,\"finae\":1611831212.324154,\"wnzbcanrlyfn\":false,\"bqvdyy\":1710644878.7505925,\"vjovx\":true,\"xlnhnbrnitri\":true,\"gtjmqdyvq\":-1408362857.4419587,\"sygwgrdr\":\"Qxq1GQbAYZ_-Go-EDqbk\",\"dbvjd\":72963880.37368356,\"raslib\":true,\"khiqqyizlohe\":1942786477.2427585,\"mppngxhpd\":\"PHQH\",\"bwikbgppxxh\":false,\"okapngskkybx\":\"MiSI-Sf2LLnv6AI51\",\"pskvne\":false,\"bdxygaxcuwi\":969765955.0997615,\"nvjlav\":-2111177640,\"oscecsvaa\":\"eGzPcPvXB4OPWyA5-bU\"},\"gMVlm-k\",-1030551635,-1583874238,{\"hxwcrkro\":\"AO7-D1H0V8\",\"cqtcju\":1069098535.932761,\"godpdjcsqh\":-150858763,\"ajrlabjr\":true,\"dflyst\":true,\"pxldcavw\":\"fW-NQlQCGZ\",\"jfcbe\":\"8bc1YY\",\"xuspvssuh\":\"Y\",\"uokjwm\":false,\"kcbvmlkvq\":\"FBgh-nZ6328QMHr_m\",\"urfaadjfs\":\"L9Tplxbr_\",\"kpkgl\":\"g4w9bS3VDhs\",\"atzwsfokaol\":\"6WpX4pRm2fdGK\",\"bhscqe\":1498434327,\"kdfowzivhr\":true,\"ozhporzqad\":-997617046.5037124,\"jxhnno\":-461939541,\"salmvni\":false,\"cjpkdlb\":true,\"upkjdv\":-1774286722,\"jkxzjgvrdnd\":\"Xp_Dup\",\"absnyqlkx\":617565230.4996662,\"lbdzgnrdfsd\":\"B7YbV-8YSCq1sb5hgw1\"},-1001429990.0885692,403366567.97560805,false,\"G2B1epoqBwho_TFhXW\",{\"gptjeryxcl\":1374088948.3081834,\"kxflfsd\":false,\"jsiphcxk\":false,\"bjxnw\":-1871978968,\"kegybhpw\":true,\"nnnpsysw\":\"VvuuXP6OmnS38hYCkxJD\",\"azgmsjbhfvyf\":-1602747627,\"slaqtpooxrna\":\"ORTIFQW-9\",\"onhwafugrgh\":true,\"zvpaptr\":-876432766,\"mqrkmhayid\":-2089081333,\"gcsdcl\":672078634.9836928,\"cjdsgkpb\":-151246824.82436705,\"hhbaqrlbsemd\":true,\"nvngmmpaynjs\":false,\"ffnndjxkgd\":423988000.15775263}],[[\"ElQ\",true,false,\"iv\",-85606793.28443319,965250803,\"U0fHc6MA7NYH6XQcGh3d\",false],-1535841679,\"bjGACK\",[307245877.4837667,\"JhWc_pNxb\",true,\"5CdXdC2L\",false,1003244012,true,false,false],false,[\"ZdlwD9Cq5SrG\",-1821921395.6349301,\"zTKPKkNzcMx_\",false,\"N_287DgT9JpjsAzGh\",\"JUV5U\",1019833798,1372047613.556522,1265995629,false,-895172602.2046804,\"3d-hYu\",false],-1407574220,{\"rynmnxsasb\":-653304745.0893059,\"jbibhpjayqp\":730148923,\"cixxvjg\":-25407104.769711196,\"gpehslkz\":-1300928753,\"tiemoqdgsu\":true,\"bomufie\":-576486278.7590132,\"zebaacqngv\":false,\"ndvfwb\":-585424136,\"ueysx\":-356937114.225807,\"foerhpa\":false},\"4yWBpJ7bb\",1569231724,true,false,-1250601371,false,\"4pJV9D\",[769954158.0885214,false,-1791365204.7887144,false,\"PoZ8l\",\"0fDoVQliIuESnO\",false,false,\"FCjAGW9N0AGSRRb0Vy\",true,true,-38160703,\"5\",\"_cA0BUlP9MfZPfLw4\",-1898658731,369392461.81777865,false,false,false,\"r_VVOH\",false,\"R4MmMZLZgbmzUan1Jq\",\"YSa\",-1962948899.4077523,true,\"T\",true,-1140486483.3740618,-737347607],1351324126.5574043,{\"qsitzi\":true,\"fijgdjgk\":-967205444,\"nbqkdzkrjgj\":933424952.697312,\"kgvbt\":1625313329,\"txxbhnj\":-2080554836.1231666,\"yipucemhb\":\"jEv\",\"jtidugkw\":1166039838,\"xfzdk\":-146687097,\"zmhncn\":1240639305,\"poqfafekfx\":-1011576371,\"qxesosqpeeqq\":\"j5EupLvqExpNm6jMfe00\",\"fjjthybwayk\":true,\"auhzlzwpii\":false,\"audnceagpqje\":true,\"ngjepmttb\":1951637988.1159675,\"cxzogbc\":false,\"dyhudslo\":1029126088,\"zifsygos\":true,\"qktbvfztf\":\"xMKBG6VOG7qdAXd5dP\",\"caxgmhj\":-232647357.09506717,\"ljxrwtpu\":false,\"rcdwfrwdkeza\":\"vk7S3r-eez\",\"jisiywqooru\":1880296376.280233,\"mbvufobhimbf\":2099577665,\"upwqvokqn\":277465317},[2042002974,396795477.4198367],[\"GOPvC3dvLoukBRwZW\",-795842489.7359524,\"KS81Oa8\",false,940382380,true,400309049.55128443,436047811],false,[\"pltqhM86Hk\",true,855546412.9572027,\"xbAd6LJJbm0k\",true,791814583,\"P\",-831944503,false,\"sgPgK3oHQrBFTV\",\"rYzdX6P\",true,\"oR-7LbhD00_sMQE\",\"EBLnFCJ8LWGA\",-839992624,false,766889618,2021141059,false,false,\"7xXu-xF9qMJ\",false,\"T0bFCwG_3q7qA2gwMw\",false,\"Q3dy1nBbHdqfB2w1k_MR\",369213829,true,false,-1547751718.724593,-624241454],{\"zdyzev\":751872301.4874185,\"hhgqstr\":-1173175611.8292267,\"lrllpibtipxr\":false,\"lzxigro\":false,\"ayntrcmljpoq\":2083870563,\"idqpaq\":\"odtI-r\",\"cvgevfdllny\":-1000638405.0909553,\"tplbmqwgihz\":1357229246.361464,\"klguszw\":true,\"gvaurzxdxne\":1602296418,\"ujuzcmwqrwau\":-651036568.647183,\"vnirbqntpleg\":\"G2RAL2uYOo1RK5i105w\",\"csjpq\":false,\"cwtpqray\":-367032734.1691864,\"nfnuav\":\"qSDW0D7YmfmTUKFQmpNO\",\"npvwvbde\":1086644217.340395},{\"vxlwbkfnlvx\":1498370431.8177407,\"lzyvnnr\":true,\"fkjwofhq\":true,\"sgnebpr\":false,\"zffifet\":\"8PxdSOtCcYO\",\"jcsrzvjye\":true,\"lccyrhym\":\"BTUILZxW5ESCO82MgKdI\",\"cvxttndsgm\":290113306.1706568,\"ggiyubsyed\":\"XrIzRD\"},\"xEIXWW\",-519527993,{\"kbpth\":true,\"xxzgkgx\":\"-5rCpn-o1erqd-h\",\"tprguihaendy\":-663375272.6692579,\"nwsxyqtqf\":905947043,\"dhmlwknfkf\":\"nX1GqsWx\",\"elvnocnwe\":\"uQ-9YpSS-Nsgthi9\",\"jpmqjj\":\"ZJiK\",\"cofknaloxspy\":1260131393,\"aidoipohmog\":true,\"esslxakaoxb\":530015070.39062315,\"wcmtanmn\":-98599681},\"r4\",\"TgByuS\",[906778980.9215955,false,1223927131,true,false,\"1VtYoxJ2d9c5Pqj\",\"vBQHkCx\",-57433142,false,true,true,\"Hy6H8WYAFGcv\",\"YNd4C9i0SD75zN8YF\",false,true,false,\"dSYJvHjvg\",false,\"P\",\"aSmYt4X3xYS3QcVti\",12586457,\"8fcxKbi\",\"rT-a\",true,\"6sSq\",-1442649739,false,-175121496]],1970495764,\"iox_\",true,\"ja1GT5opGzT_Wpv\",-1293998686.9086683,\"4T_nYlwHeugeKO4SA8qS\",{\"kyaunkwoxir\":-1217597389,\"zctdtewdq\":-1286402733,\"vxbwfew\":-1026603695.8885456,\"jrljn\":true,\"gakgbepxuamk\":{\"ynnpqaiam\":\"bzlvY4_sD_vtqYIIW\",\"qmyfpqlxpi\":\"I\",\"kpzuiznpblup\":629437193.4853684,\"nmnfedseqed\":false,\"dnmcklpvoxw\":\"lb69Qig\",\"fqbyqyyxjjlv\":\"DcEd0HLtMhyF\",\"rpbqydlbifu\":false,\"ybkvdnaptmvn\":380272527,\"powdrfw\":731035398,\"agfshh\":1727717448,\"mwkjp\":\"J-Q91\",\"kbpibing\":-1275369939,\"luejqxefawqr\":-1950419331,\"fmdpzer\":\"NN9TAdrvYUiI\",\"ewdetcv\":true,\"urxeot\":1988656520.399121,\"umtdbj\":1374160030.9786549,\"kbsemvnncc\":false,\"ltmrewplxzf\":-644505270.3136207,\"sqjgcqto\":-596928812,\"rltxvxo\":\"xOoTUGDiQHNqSW0H\",\"zzboptbhxq\":false,\"ojfbytx\":\"znh8mtHicoUVJkxrME\",\"aosutv\":\"lu6KHbHC36iJ2\",\"bblebrzz\":1228891813.5832617,\"ruymenhkkvpm\":\"ugh1\"},\"dfxecgbcdxz\":{\"jstczk\":-1680171538.576234,\"bnbzfyej\":-653278353.0596074,\"efxfypiolu\":false,\"dxwkfpva\":-886677278,\"rrhehzirc\":true,\"jlvvqu\":-1697967237,\"vrmyg\":-138326010.05602455,\"mzvduwyaehy\":1175182985.4112437,\"nxqjxwkcxv\":\"TKQZqV\",\"qluvunpr\":\"6mqIPuNPE0\",\"ksmkpkkho\":true,\"mnvzwdz\":\"JHThsHD2w5mlc\",\"bupdetrk\":true,\"abyfpmjbzg\":true,\"khaimscqmji\":-1404839480.8220131,\"vtcjsj\":true},\"ivzfqzb\":{\"nknmphwejnq\":true,\"ufvnzcyg\":\"47AlwUS_FmPCyN\",\"ueobe\":false,\"feyyqivlji\":true,\"zcjuwq\":false,\"vyyhmf\":\"92ASvU\",\"jnadvmtd\":\"YKE71MMcAVvkxFvrJ-G\",\"ikmgaazbpuh\":false,\"gsppw\":\"dHEK_0u\"}},true]";
            Console.WriteLine("length {0} string :", raw.Length, raw);
            string publicKey = "BGoz+60OlJNspdxYmhqPi77HtGo//murT4D2B2/jMY8+rycFSCl8skdTO0JMyAKfd3Pnno71IXumlEpvuPmyeMs=";
            byte[] cipherBytes = CryptoUtils.Sm2Encrypt(Convert.FromBase64String(publicKey), Encoding.UTF8.GetBytes(raw));
            Console.WriteLine("length {0} cipher：{1}", cipherBytes.Length, Convert.ToBase64String(cipherBytes));
        }

        /// <summary>
        /// sm2加密测试
        /// </summary>
        [TestMethod]
        public void Sm2DecryptTest()
        {
            string raw = "{\"acbvrtyvpdc\":[\"d\",\"dlGWKpozTC94wW5JXsWO\",{\"tigawc\":-380956822.11672634,\"xtgkkxveldv\":false,\"dxlmhpctvef\":true,\"fannraqwn\":true,\"nkosodsl\":false,\"msbem\":238258173,\"bziywrix\":707882406,\"ovtdnxxoi\":-1806667753,\"rhsnowlqck\":-1608455663,\"wlwel\":-540019786}],\"xsjka\":1340367098.8789954,\"ydryl\":{\"mrifjgzcgw\":false,\"oankwgx\":\"dPUd\",\"enlhqrzuzxs\":false,\"jweuvl\":{\"yzrmkavkokf\":-968350209,\"ihnkcyw\":-223589607.23376453,\"wixllqna\":false,\"epkuh\":true,\"zitsspg\":true,\"enuxohldd\":1598433655,\"nypkgiofkhan\":\"_L9neFLfa50ybCPrbE\"},\"misuf\":true,\"qmdmpikvo\":-248620711.32979456,\"kpolznqql\":true},\"xsgfbwxewcii\":-1578433480,\"oeocpvble\":2053314289.393429}";
            string cipher = "BGIpgNF0RzmYYYaSzRRqnWmvs92Svml1TuRCIbWCKzhn5O4Zftqd8RtctQBFQ+at38vT5kgCNpCDgym1YIyEiyGlwkyDwi6ynowMWg4GxbUI5wBbs24MFQzU2mmBnb5Tg2pzyvl0kXFQCXQaWtB3pZsoMEbxPWx6YrW+8rGfj7tf2iN8OXwU4ghYcb2j6Hd70n5RRk85ZuzG+IesMDtykgGJtif+nd52yL4z6o826HOsDtnK9mAFeSkOciEgMSc5+fLEm6EHbHSUaZVqnvqudv0bFZqUffstgPHdA1S3RlVfQ2btVjBzT19CU9OHz1AI0gNFhozU687DdqeJIWDvEdSBDQKqMCGlc9VBp3X23CEQhg7dFFMK2b0VJGrhAXjy+JtixJrKb49AMpLUKIoQYOh+fF1EVdSWzyOJg/Rc4h052XV7mYd6A5scQFFjZBOm4I+xJSjpMCah5ooRo3GNlzRuwUfEuxYjGvQvHAep8kGnp+ofnd2A3YJhkKDq/vxMAC7sxK5JrzW9qHhQBiNUZuRBEFTbXbQWlCGhPHpz6TpKXDkcYxokV4JS7c/dTlN0IOcQRkF0xrJiVzhSVhSomljohrOYn6LCG8Ce7s6YD5JdRu67oksFUFfWAi0dHTUXw51U9zKNOnU81gcOsfg+TPn6X83m6YE8SkWqKOzs18v1pBgDPcMZQJClIeKo7XBj3uCQekH+dUbrY+gHhE1/lP8rQUS3yw7cJHR2Gg6HaYHyTgz5mVLfOy9sBT8aHwfi28tZi2jO59qbl3zbdRAeBSA+RrLFvIvjTvV2otISdu1QDJ6cJsoh8a/Ar+J+Y9Kq9ZtihwU5EZBs+bRKCKyrmzoqv9WL68qrwm/NooYhbhM9wFi0zaorulNGHwDr6YwhUKRLEva4KY4mqFdCCUb3eyh2+e0bvIPYSXpC2I0kDp0roTlH2q6tlqNAQg/Tp+VZoj+OtGB9yGH11xgLcR8=";
            string privateKey = "Vsf5WA8Aggvi6kb7lGgm1vQEJhNzPvDoQ0/ZQzbfAnc=";
            byte[] plainBytes = CryptoUtils.Sm2Decrypt(Convert.FromBase64String(privateKey), Convert.FromBase64String(cipher));
            string plain = Encoding.UTF8.GetString(plainBytes);
            Console.WriteLine("plain:" + plain);
            Assert.AreEqual(raw, plain);
        }

        /// <summary>
        /// SM2 GM加密测试
        /// </summary>
        [TestMethod]
        public void GmEncryptTest()
        {
            string raw = "0bc6f81c613d4038";
            string publicKey = "BGoz+60OlJNspdxYmhqPi77HtGo//murT4D2B2/jMY8+rycFSCl8skdTO0JMyAKfd3Pnno71IXumlEpvuPmyeMs=";

            Org.BouncyCastle.Asn1.X9.X9ECParameters Sm2EcParameters = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName("sm2p256v1");
            Org.BouncyCastle.Crypto.Parameters.ECDomainParameters DomainParameters = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(Sm2EcParameters.Curve, Sm2EcParameters.G, Sm2EcParameters.N);
            Org.BouncyCastle.Crypto.Engines.SM2Engine cipher = new Org.BouncyCastle.Crypto.Engines.SM2Engine();
            Org.BouncyCastle.Math.EC.ECPoint ecPoint = DomainParameters.Curve.DecodePoint(Convert.FromBase64String(publicKey));
            Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters publicKeyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(ecPoint, DomainParameters);
            Org.BouncyCastle.Crypto.Parameters.ParametersWithRandom parametersWithRandom = new Org.BouncyCastle.Crypto.Parameters.ParametersWithRandom(publicKeyParameters);
            cipher.Init(true, parametersWithRandom);

            byte[] rawBytes = Encoding.UTF8.GetBytes(raw);
            byte[] cipherBytes = cipher.ProcessBlock(rawBytes, 0, rawBytes.Length);
            Console.WriteLine("cipherBytes length:{0}，base64:{1}", cipherBytes.Length, Convert.ToBase64String(cipherBytes));

            //c1 ecpoint
            int mCurveLength = (DomainParameters.Curve.FieldSize + 7) / 8;
            byte[] c1 = new byte[mCurveLength * 2 + 1];
            Array.Copy(cipherBytes, 0, c1, 0, c1.Length);
            Org.BouncyCastle.Math.EC.ECPoint c1P = DomainParameters.Curve.DecodePoint(c1);

            //c2 source
            byte[] c2 = new byte[cipherBytes.Length - c1.Length - 32];
            Array.Copy(cipherBytes, c1.Length, c2, 0, c2.Length);

            //c3 digest
            byte[] c3 = new byte[32];
            Array.Copy(cipherBytes, c1.Length + c2.Length, c3, 0, c3.Length);

            //asn1 c1->x c1->y c3 c2:
            Org.BouncyCastle.Asn1.DerInteger x = new Org.BouncyCastle.Asn1.DerInteger(c1P.XCoord.ToBigInteger());
            Org.BouncyCastle.Asn1.DerInteger y = new Org.BouncyCastle.Asn1.DerInteger(c1P.YCoord.ToBigInteger());
            Org.BouncyCastle.Asn1.DerOctetString derDig = new Org.BouncyCastle.Asn1.DerOctetString(c3);
            Org.BouncyCastle.Asn1.DerOctetString derEnc = new Org.BouncyCastle.Asn1.DerOctetString(c2);
            Org.BouncyCastle.Asn1.Asn1EncodableVector v = new Org.BouncyCastle.Asn1.Asn1EncodableVector();
            v.Add(x);
            v.Add(y);
            v.Add(derDig);
            v.Add(derEnc);
            Org.BouncyCastle.Asn1.DerSequence seq = new Org.BouncyCastle.Asn1.DerSequence(v);
            byte[] bankBytes = seq.GetEncoded();
            Console.WriteLine("gm cipher：{0}", Convert.ToBase64String(bankBytes));
        }

        /// <summary>
        /// SM2 gm格式解密测试
        /// </summary>
        [TestMethod]
        public void GmDecryptTest()
        {
            string privateKey = "Vsf5WA8Aggvi6kb7lGgm1vQEJhNzPvDoQ0/ZQzbfAnc=";
            string cipher = "MHgCIFaJ7a5/AAKQ5IdY9Go854qA5ex5yy0J+rr6ncwTJ50RAiBQsFhJya/PBW5Pj+ksgZBAzCbGr+kTi7yOm6itlcQGMgQgY50OaWXXSoEK2c7M/n6qNBeakKADO+qM8qxueORxYbMEEH+HDmCRIXx44tiyQaIpk2g=";
            Org.BouncyCastle.Asn1.Asn1Sequence sequence = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(Convert.FromBase64String(cipher));
            System.Collections.IEnumerator? e = sequence.GetEnumerator();

            //c1->x
            e.MoveNext();
            Org.BouncyCastle.Asn1.DerInteger x = Org.BouncyCastle.Asn1.DerInteger.GetInstance(e.Current);
            //c1->y
            e.MoveNext();
            Org.BouncyCastle.Asn1.DerInteger y = Org.BouncyCastle.Asn1.DerInteger.GetInstance(e.Current);

            //c1 point
            Org.BouncyCastle.Asn1.X9.X9ECParameters Sm2EcParameters = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName("sm2p256v1");
            Org.BouncyCastle.Crypto.Parameters.ECDomainParameters DomainParameters = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(Sm2EcParameters.Curve, Sm2EcParameters.G, Sm2EcParameters.N);
            Org.BouncyCastle.Math.EC.ECPoint c1 = DomainParameters.Curve.CreatePoint(x.Value, y.Value);
            byte[] c1Bytes = c1.GetEncoded();

            //c3 source
            e.MoveNext();
            Org.BouncyCastle.Asn1.Asn1OctetString c3 = Org.BouncyCastle.Asn1.DerOctetString.GetInstance(e.Current);
            byte[] c3Bytes = c3.GetOctets();

            //c2 digest
            e.MoveNext();
            Org.BouncyCastle.Asn1.Asn1OctetString c2 = Org.BouncyCastle.Asn1.DerOctetString.GetInstance(e.Current);
            byte[] c2Bytes = c2.GetOctets();

            //gm是c1 c3 c2
            //bc标准是c1 c2 c3
            byte[] cipherBytes = new byte[c1Bytes.Length + c2Bytes.Length + c3Bytes.Length];
            Array.Copy(c1Bytes, 0, cipherBytes, 0, c1Bytes.Length);
            Array.Copy(c2Bytes, 0, cipherBytes, c1Bytes.Length, c2Bytes.Length);
            Array.Copy(c3Bytes, 0, cipherBytes, c1Bytes.Length + c2Bytes.Length, c3Bytes.Length);

            byte[] plainBytes = CryptoUtils.Sm2Decrypt(Convert.FromBase64String(privateKey), cipherBytes);
            string raw = Encoding.UTF8.GetString(plainBytes);

            Assert.AreEqual("0bc6f81c613d4038", raw);
        }
    }
}