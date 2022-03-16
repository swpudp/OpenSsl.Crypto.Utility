using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// 数据签名测试
    /// </summary>
    [TestClass]
    public class SignatureUtilsTests
    {
        /// <summary>
        /// 签名测试
        /// </summary>
        [TestMethod]
        public void RsaSignTest()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string data = "123456";

            byte[] signBytes = SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);

            //hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("RsaSignTest->sign Hex:" + sign);

            //hex转base64
            Console.WriteLine("RsaSignTest->sign Base64:" + Convert.ToBase64String(signBytes));

            //hex转自定义编码
            string simpleSign = SimpleCoder.EncodeBytes(signBytes);
            Assert.IsNotNull(simpleSign);
            Console.WriteLine("RsaSignTest->sign SimpleCoder:" + simpleSign);
        }

        /// <summary>
        /// 验签测试
        /// </summary>
        [TestMethod]
        public void RsaVerifyTest()
        {
            string publicKey =
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";

            //hex
            string signHex =
"20a766e18f7c35d1b7e8326ed5810c5118858b1679841f9b281c3a55d9ff11a471057db868579e002a9c9e5dbb052d471903eba8a5e22c8dd2955f0ecf2fe0f611363f29b327111ef1b0f74f69014eaee24b7e30ae391f5601f312f0e053aca2422b9123ece962a13aaf6840b13d27242eccc8b6f02282735c55ecaf56226d66";
            bool isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(signHex), RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);

            //base64
            string signBase64 =
                "IKdm4Y98NdG36DJu1YEMURiFixZ5hB+bKBw6Vdn/EaRxBX24aFeeACqcnl27BS1HGQPrqKXiLI3SlV8Ozy/g9hE2PymzJxEe8bD3T2kBTq7iS34wrjkfVgHzEvDgU6yiQiuRI+zpYqE6r2hAsT0nJC7MyLbwIoJzXFXsr1YibWY=";
            Assert.AreEqual(signBase64, Convert.ToBase64String(HexUtils.ToByteArray(signHex)));

            isSign = SignatureUtils.RsaVerify(publicKey, data, Convert.FromBase64String(signBase64), RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);

            //自定义编码
            string signSimple = "MjBhNzY2ZTE4ZjdjMzVkMWI3ZTgzMjZlZDU4MTBjNTExODg1OGIxNjc5ODQxZjliMjgxYzNhNTVkOWZmMTFhNDcxMDU3ZGI4Njg1NzllMDAyYTljOWU1ZGJiMDUyZDQ3MTkwM2ViYThhNWUyMmM4ZGQyOTU1ZjBlY2YyZmUwZjYxMTM2M2YyOWIzMjcxMTFlZjFiMGY3NGY2OTAxNGVhZWUyNGI3ZTMwYWUzOTFmNTYwMWYzMTJmMGUwNTNhY2EyNDIyYjkxMjNlY2U5NjJhMTNhYWY2ODQwYjEzZDI3MjQyZWNjYzhiNmYwMjI4MjczNWM1NWVjYWY1NjIyNmQ2Ng==";
            byte[] signSimpleBytes = SimpleCoder.DecodeBytes(signSimple);

            isSign = SignatureUtils.RsaVerify(publicKey, data, signSimpleBytes, RsaSignerAlgorithm.SHA1withRSA);
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

            string sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.MD2withRSA));
            Assert.IsNotNull(sign);
            bool isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.MD2withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.MD5withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.MD5withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA224withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA224withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA256withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA256withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA384withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA384withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA512withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA512withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.RIPEMD128withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.RIPEMD128withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.RIPEMD160withRSA));
            Assert.IsNotNull(sign);
            Console.WriteLine(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.RIPEMD160withRSA);
            Assert.AreEqual(true, isSign);
        }

        [TestMethod]
        public void Sm2SignTest()
        {
            string privateKey = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
            string content = "123456";

            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content);

            //hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignTest->sign hex：" + sign);

            //hex转base64
            Console.WriteLine("Sm2SignTest->sign Base64:" + Convert.ToBase64String(signBytes));

            //hex转自定义编码
            string simpleSign = SimpleCoder.EncodeDERBytes(signBytes);
            Assert.IsNotNull(simpleSign);
            Console.WriteLine("Sm2SignTest->sign SimpleCoder:" + simpleSign);
        }

        [TestMethod]
        public void Sm2VerifyTest()
        {
            string content = "123456";
            string publicKey = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";

            //hex
            string signHex = "304402200ed5bdb7102a1b91ff86a8b39f7e9a3ed3967bc51f1640a60f64cd562f1afac702206eec6c52389b4e9c2ba3548a963abc91d8b8571138427d438bbd4ffb2fcf9f4f";
            bool isSuccess = SignatureUtils.Sm2Verify(publicKey, content, HexUtils.ToByteArray(signHex));
            Assert.AreEqual(true, isSuccess);

            //base64
            string signBase64 = "MEQCIA7VvbcQKhuR/4aos59+mj7TlnvFHxZApg9kzVYvGvrHAiBu7GxSOJtOnCujVIqWOryR2LhXEThCfUOLvU/7L8+fTw==";
            isSuccess = SignatureUtils.Sm2Verify(publicKey, content, Convert.FromBase64String(signBase64));
            Assert.AreEqual(true, isSuccess);

            //自定义编码
            string signSimple = "2fa1a4cca95f1c85a94dd13082dc313e40cc075169bb89f4d1cecce420a4576a391ef6f4173411c6a716483743d291d2e285c1db3a13b48587b9538933de51b4";
            byte[] signSimpleBytes = SimpleCoder.DecodeDERBytes(signSimple);
            isSuccess = SignatureUtils.Sm2Verify(publicKey, content, signSimpleBytes);
            Assert.AreEqual(true, isSuccess);
        }
    }
}