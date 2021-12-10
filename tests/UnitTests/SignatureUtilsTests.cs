using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;
using System;
using System.Text;
using UnitTests;

namespace UnitTests
{
    /// <summary>
    /// 数据签名测试
    /// </summary>
    [TestClass]
    public class SignatureUtilsTests
    {
        /// <summary>
        /// 签名测试（Base64）
        /// </summary>
        [TestMethod]
        public void RsaSignToBase64Test()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string data = "123456";
            string sign = SignatureUtils.RsaSignToBase64(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);
            Assert.IsNotNull(sign);
            Console.WriteLine("RsaSignToBase64->sign:" + sign);
        }

        /// <summary>
        /// 签名测试（Hex）
        /// </summary>
        [TestMethod]
        public void RsaSignToHexTest()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string data = "123456";
            string sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);
            Assert.IsNotNull(sign);
            Console.WriteLine("RsaSignToHexTest->sign:" + sign);
        }

        [TestMethod]
        public void RsaSignToBytesTest()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string data = "123456";
            byte[] signBytes = SignatureUtils.RsaSignToBytes(Convert.FromBase64String(privateKey), Encoding.UTF8.GetBytes(data), RsaSignerAlgorithm.SHA1withRSA);
            Assert.IsNotNull(signBytes);
            string sign = Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("RsaSignToBytesTest->sign:" + sign);
        }

        /// <summary>
        /// 验签测试（Bytes）
        /// </summary>
        [TestMethod]
        public void RsaVerifyFromBytesTest()
        {
            string publicKey =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";
            string sign =
                "20a766e18f7c35d1b7e8326ed5810c5118858b1679841f9b281c3a55d9ff11a471057db868579e002a9c9e5dbb052d471903eba8a5e22c8dd2955f0ecf2fe0f611363f29b327111ef1b0f74f69014eaee24b7e30ae391f5601f312f0e053aca2422b9123ece962a13aaf6840b13d27242eccc8b6f02282735c55ecaf56226d66";
            bool isSign = SignatureUtils.RsaVerifyFromBytes(Convert.FromBase64String(publicKey), Encoding.UTF8.GetBytes(data),
                Org.BouncyCastle.Utilities.Encoders.Hex.Decode(sign), RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);
        }

        /// <summary>
        /// 验签测试（Hex）
        /// </summary>
        [TestMethod]
        public void RsaVerifyFromHexTest()
        {
            string publicKey =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";
            string sign =
                "20a766e18f7c35d1b7e8326ed5810c5118858b1679841f9b281c3a55d9ff11a471057db868579e002a9c9e5dbb052d471903eba8a5e22c8dd2955f0ecf2fe0f611363f29b327111ef1b0f74f69014eaee24b7e30ae391f5601f312f0e053aca2422b9123ece962a13aaf6840b13d27242eccc8b6f02282735c55ecaf56226d66";
            bool isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);
        }

        /// <summary>
        /// 验签测试（Base64）
        /// </summary>
        [TestMethod]
        public void RsaVerifyFromBase64Test()
        {
            string publicKey =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";
            string sign =
                "IKdm4Y98NdG36DJu1YEMURiFixZ5hB+bKBw6Vdn/EaRxBX24aFeeACqcnl27BS1HGQPrqKXiLI3SlV8Ozy/g9hE2PymzJxEe8bD3T2kBTq7iS34wrjkfVgHzEvDgU6yiQiuRI+zpYqE6r2hAsT0nJC7MyLbwIoJzXFXsr1YibWY=";
            bool isSign = SignatureUtils.RsaVerifyFromBase64(publicKey, data, sign, RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);
        }

        /// <summary>
        /// RSA签名其他算法类型测试
        /// </summary>
        [TestMethod]
        public void RsaSignWithOtherAlgorithmTest()
        {
            string privateKey =
                "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string publicKey =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";

            string sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.MD2withRSA);
            Assert.IsNotNull(sign);
            bool isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.MD2withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.MD5withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.MD5withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA224withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA224withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA256withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA256withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA384withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA384withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.SHA512withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.SHA512withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.RIPEMD128withRSA);
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.RIPEMD128withRSA);
            Assert.AreEqual(true, isSign);

            sign = SignatureUtils.RsaSignToHex(privateKey, data, RsaSignerAlgorithm.RIPEMD160withRSA);
            Assert.IsNotNull(sign);
            Console.WriteLine(sign);
            isSign = SignatureUtils.RsaVerifyFromHex(publicKey, data, sign, RsaSignerAlgorithm.RIPEMD160withRSA);
            Assert.AreEqual(true, isSign);
        }

        [TestMethod]
        public void Sm2SignToHexTest()
        {
            string privateKey = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
            string content = "123456";
            string sign = SignatureUtils.Sm2SignToHex(privateKey, content);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignToHexTest->sign：" + sign);
        }

        [TestMethod]
        public void Sm2SignToBase64Test()
        {
            string privateKey = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
            string content = "123456";
            string sign = SignatureUtils.Sm2SignToBase64(privateKey, content);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignToBase64Test->sign:" + sign);
        }

        [TestMethod]
        public void Sm2SignToBytesTest()
        {
            string privateKey = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
            string content = "123456";
            byte[] signBytes = SignatureUtils.Sm2SignToBytes(privateKey, content);
            string sign = SimpleCoder.EncodeBytes(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignToBytesTest->sign：" + sign);
        }

        [TestMethod]
        public void Sm2VerifyFromBase64Test()
        {
            string content = "123456";
            string publicKey = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";
            string sign = "MEUCIHa9L0fTR+NfyXzujhyRmCut2yhpgibRY83rRmFO+2MZAiEAi5BEsaQusGBAQR3KVA+XneofYCEHlvHadHn07ljCFjE=";
            bool isSuccess = SignatureUtils.Sm2VerifyFromBase64(content, publicKey, sign);
            Assert.AreEqual(true, isSuccess);
        }

        [TestMethod]
        public void Sm2VerifyFromHexTest()
        {
            string content = "123456";
            string publicKey = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";
            string sign = "3045022100df46277276b6c5fa8e80b64c13f9c025d19204ad5f6eb474404ccaecfe09a9ef02203036e60e91917b62bd367cb8da3f22da1d353dee32b9b61fad66045fc8fcd9f2";
            bool isSuccess = SignatureUtils.Sm2VerifyFromHex(content, publicKey, sign);
            Assert.AreEqual(true, isSuccess);
        }

        [TestMethod]
        public void Sm2VerifyFromBytesTest()
        {
            string content = "123456";
            string publicKey = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";
            string sign = "MzA0NjAyMjEwMGJjMzEwNjVlMGE0OGY5YzBkYmIxNGY3NWU5ZTQ2ZjkzNTEzY2IwOGZjYTcxMThjMWIzMzI4NzM5NWM0MTE5OTYwMjIxMDBhZWRlNGE5NGU1OTM4MWEwYTBlNDRhZmUzZDU4NjI0ZTYzNGZlNDRmMWU1ZmNhZjMzMThmZDEzOTFjYzhmZGE2";
            byte[] signResultBytes = SimpleCoder.DecodeBytes(sign);
            bool isSuccess = SignatureUtils.Sm2VerifyFromBytes(content, publicKey, signResultBytes);
            Assert.AreEqual(true, isSuccess);
        }
    }
}