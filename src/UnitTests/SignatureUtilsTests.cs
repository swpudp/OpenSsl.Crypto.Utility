using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

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
            string privateKeyBase64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string source = "123456";
            byte[] data = Encoding.UTF8.GetBytes(source);

            byte[] privateKey = Convert.FromBase64String(privateKeyBase64);
            byte[] signBytes = SignatureUtils.RsaSign(privateKey, data, RsaSignerAlgorithm.SHA1withRSA);

            //hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("RsaSignTest->sign Hex:" + sign);

            //hex转base64
            Console.WriteLine("RsaSignTest->sign Base64:" + Convert.ToBase64String(signBytes));
        }

        /// <summary>
        /// 验签测试
        /// </summary>
        [TestMethod]
        public void RsaVerifyTest()
        {
            string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string data = "123456";
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] sourceBytes = Encoding.UTF8.GetBytes(data);

            //hex
            string signHex = "20a766e18f7c35d1b7e8326ed5810c5118858b1679841f9b281c3a55d9ff11a471057db868579e002a9c9e5dbb052d471903eba8a5e22c8dd2955f0ecf2fe0f611363f29b327111ef1b0f74f69014eaee24b7e30ae391f5601f312f0e053aca2422b9123ece962a13aaf6840b13d27242eccc8b6f02282735c55ecaf56226d66";
            bool isSign = SignatureUtils.RsaVerify(publicKeyBytes, sourceBytes, HexUtils.ToByteArray(signHex), RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);

            //base64
            string signBase64 = "IKdm4Y98NdG36DJu1YEMURiFixZ5hB+bKBw6Vdn/EaRxBX24aFeeACqcnl27BS1HGQPrqKXiLI3SlV8Ozy/g9hE2PymzJxEe8bD3T2kBTq7iS34wrjkfVgHzEvDgU6yiQiuRI+zpYqE6r2hAsT0nJC7MyLbwIoJzXFXsr1YibWY=";
            Assert.AreEqual(signBase64, Convert.ToBase64String(HexUtils.ToByteArray(signHex)));

            isSign = SignatureUtils.RsaVerify(publicKeyBytes, sourceBytes, Convert.FromBase64String(signBase64), RsaSignerAlgorithm.SHA1withRSA);
            Assert.AreEqual(true, isSign);
        }

        /// <summary>
        /// RSA签名其他算法类型测试
        /// </summary>
        [TestMethod]
        public void RsaSignWithOtherAlgorithmTest()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMyzJXQYa6lIQ2MhmqwiK225EhfkQsjwyHDzZIt8cGxEnZJ1txv2RWB4FuE8qz+lPlqqMGPKI0LyNeDHBsUqCznScS/uEA2lNFe/ByfWPpGD2a49X7GduODbKC507NpdsKMQ0dGziwPWORilIb5q+llhYjopOfR6rRbOo20wwpPpAgMBAAECgYALEPhKYXOYkD6MYmmxOpusb9/piL6PjGzZpl7eJ5kQUVlPbKu8iEDR6UwbWyNK6o0Ha8H38xqa6Os+vqPADvjSS6y8ZjDwlJdcA82uvR4WfMkb0jWrvnm4JCA3iMjCjl4LreXfQRmt4H+QJHNl881dW43iTTnVuRSC5Y1rJEWRgQJBAOYrtoSD5DuafrHXg0WFzdf/APCN0pcwyN+gKHNQQ8rg0nzwh/fDiMJJ/qDQbY3QDAgc/sD2+dNwMK2MJffBIjECQQDjq7XAKC1ZIZJNTFx4GGLuSS75nltLNnkayr1RSa/ahIWCNb5Idv18T5aVcG3AYoFOV6rjl2B3iFXCRPcvtKc5AkBMhkoHYsZV3raysAFP8v2OC5UnZS+X3rtaRihMtmnjoL26lknOYS8t0WYb11AlLv9hDyrPww0qdAlrGcZhyc9xAkBvX8SdqAnnHGExpzVlGqjq4Ko2Op12gcNks+FBLsb0Ivgc5qWbVXpToauMl19ZSdbvuDtE8vyh/PPXAV3a3IkhAkEAyGdg3YNLS+ZnC9vMicxnzotr3/OL+4rNKY1ZR8q/EelywDtU0reVsVeSC7A0v7aj6s+TwSqhDK1J9buKnP8dWA==";
            string publicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";

            string source = "123456";
            byte[] data = Encoding.UTF8.GetBytes(source);
            byte[] publicKey = Convert.FromBase64String(publicKeyBase64);
            byte[] privateKeyBytes = Convert.FromBase64String(privateKey);

            string sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.MD2withRSA));
            Assert.IsNotNull(sign);
            bool isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.MD2withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.MD5withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.MD5withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.SHA224withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA224withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.SHA256withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA256withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.SHA384withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA384withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.SHA512withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.SHA512withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.RIPEMD128withRSA));
            Assert.IsNotNull(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.RIPEMD128withRSA);
            Assert.AreEqual(true, isSign);

            sign = HexUtils.ToHexString(SignatureUtils.RsaSign(privateKeyBytes, data, RsaSignerAlgorithm.RIPEMD160withRSA));
            Assert.IsNotNull(sign);
            Console.WriteLine(sign);
            isSign = SignatureUtils.RsaVerify(publicKey, data, HexUtils.ToByteArray(sign), RsaSignerAlgorithm.RIPEMD160withRSA);
            Assert.AreEqual(true, isSign);
        }

        [TestMethod]
        public void Sm2SignTest()
        {
            string privateKeyHex = "56b73482e86a2d922e75d5b23118ea11ad932728bd2a7b6da0233506412af1e7";
            string source = "123456";

            byte[] privateKey = HexUtils.ToByteArray(privateKeyHex);
            byte[] content = Encoding.UTF8.GetBytes(source);

            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content);
            //hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignTest->sign hex：" + sign);

            //hex转base64
            Console.WriteLine("Sm2SignTest->sign Base64:" + Convert.ToBase64String(signBytes));
        }

        [TestMethod]
        public void Sm2SignP7Test()
        {
            string sm2Base64 = "MIIDIgIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDCB5a0lv7e+9YI4NyE235Y9uT2HTcCKzHHkAmncZlKGI78KT0GUx1HIe4yXpNzK00cwggLSBgoqgRzPVQYBBAIBBIICwjCCAr4wggJhoAMCAQICBSA1UwEHMAwGCCqBHM9VAYN1BQAwXTELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEcMBoGA1UEAwwTQ0ZDQSBURVNUIFNNMiBPQ0ExMTAeFw0yMDExMjYwNjI1MjFaFw0yMjExMjYwNjI1MjFaMHQxCzAJBgNVBAYTAmNuMRUwEwYDVQQKDAxDRkNBIFRFU1QgQ0ExEDAOBgNVBAsMB0NaQkFOSzMxEjAQBgNVBAsMCUN1c3RvbWVyczEoMCYGA1UEAwwfMDQxQDU4MTI0NTFAQ1pCQU5LLU9QUkAwMDAwMDAwMTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABG3iSpf2fAyEJNmT9ChU+QA73mmX7YcmM1+NMAw0voMhsXeusSkwFB8Crtn5e3C1p8gqY9KUeHoVppRLWRrnRGmjgfQwgfEwHwYDVR0jBBgwFoAUvqZ+TT18j6BV5sEvCS4sIEOzQn8wSAYDVR0gBEEwPzA9BghggRyG7yoBAjAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3VzL3VzLTE1Lmh0bTA5BgNVHR8EMjAwMC6gLKAqhihodHRwOi8vMjEwLjc0LjQyLjMvT0NBMTEvU00yL2NybDY0MzAuY3JsMAsGA1UdDwQEAwID6DAdBgNVHQ4EFgQUqFjZ97vgrWb+dLIgtkEvbag5lG0wHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMAwGCCqBHM9VAYN1BQADSQAwRgIhAKd544GEPqAT8f/yBiQGfrPPRYsWgS1NETkadIZcbA8SAiEA91943ItuwLGRjdEf4dRYR1QiHKQYJQhHe2yeG39d8kk=";
            string pwd = "a95527";
            byte[] sm2Data = Convert.FromBase64String(sm2Base64);
            ECPrivateKeyParameters? pv = SmCertUtils.GetPrivateKeyFromP12(sm2Data, pwd);
            X509Certificate? cert = SmCertUtils.GetCertFromP12(sm2Data);

            string source = "123456";
            byte[] privateKey = SmCertUtils.GetPrivateKey(pv);
            byte[] content = Encoding.UTF8.GetBytes(source);

            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, cert, content);
            //to hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignP7Test->sign hex：" + sign);

            //to base64
            Console.WriteLine("Sm2SignP7Test->sign Base64:" + Convert.ToBase64String(signBytes));
        }

        /// <summary>
        /// 数据验证
        /// </summary>
        [TestMethod]
        public void VerifyP7Test()
        {
            //文档原创
            byte[] sourceBytes = Encoding.UTF8.GetBytes("Z000022725Z00002272021-02-04 10:47:30.88211637480324508820641");
            //文档里面的签名
            byte[] signature = Convert.FromBase64String("MIIEEwYKKoEcz1UGAQQCAqCCBAMwggP/AgEBMQ4wDAYIKoEcz1UBgxEFADBNBgoqgRzPVQYBBAIBoD8EPVowMDAwMjI3MjVaMDAwMDIyNzIwMjEtMDItMDQgMTA6NDc6MzAuODgyMTE2Mzc0ODAzMjQ1MDg4MjA2NDGgggLCMIICvjCCAmGgAwIBAgIFIDVTAQcwDAYIKoEcz1UBg3UFADBdMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRwwGgYDVQQDDBNDRkNBIFRFU1QgU00yIE9DQTExMB4XDTIwMTEyNjA2MjUyMVoXDTIyMTEyNjA2MjUyMVowdDELMAkGA1UEBhMCY24xFTATBgNVBAoMDENGQ0EgVEVTVCBDQTEQMA4GA1UECwwHQ1pCQU5LMzESMBAGA1UECwwJQ3VzdG9tZXJzMSgwJgYDVQQDDB8wNDFANTgxMjQ1MUBDWkJBTkstT1BSQDAwMDAwMDAxMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEbeJKl/Z8DIQk2ZP0KFT5ADveaZfthyYzX40wDDS+gyGxd66xKTAUHwKu2fl7cLWnyCpj0pR4ehWmlEtZGudEaaOB9DCB8TAfBgNVHSMEGDAWgBS+pn5NPXyPoFXmwS8JLiwgQ7NCfzBIBgNVHSAEQTA/MD0GCGCBHIbvKgECMDEwLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cuY2ZjYS5jb20uY24vdXMvdXMtMTUuaHRtMDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly8yMTAuNzQuNDIuMy9PQ0ExMS9TTTIvY3JsNjQzMC5jcmwwCwYDVR0PBAQDAgPoMB0GA1UdDgQWBBSoWNn3u+CtZv50siC2QS9tqDmUbTAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANJADBGAiEAp3njgYQ+oBPx//IGJAZ+s89FixaBLU0RORp0hlxsDxICIQD3X3jci27AsZGN0R/h1FhHVCIcpBglCEd7bJ4bf13ySTGB1DCB0QIBATBmMF0xCzAJBgNVBAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxHDAaBgNVBAMME0NGQ0EgVEVTVCBTTTIgT0NBMTECBSA1UwEHMAwGCCqBHM9VAYMRBQAwDQYJKoEcz1UBgi0BBQAERzBFAiATr0Pr1Je+g3zk4l74IBoomA/Ctwym+78m/MJuR7ssGgIhAOFHxRzAc8dHu+e4szuvJjrphrBYDKuIk39e5rKWA8Gn");
            bool isOk = SignatureUtils.Sm2Verify(sourceBytes, signature);
            Assert.IsTrue(isOk);
        }

        /// <summary>
        /// 生成证书测试
        /// </summary>
        [TestMethod]
        public void CreateP12FileTest()
        {
            string p12Pwd = "12345678";
            string p12 = SmCertUtils.CreateP12File("sk-test", "sk", p12Pwd);

            byte[] sm2Data = Convert.FromBase64String(p12);
            ECPrivateKeyParameters? pv = SmCertUtils.GetPrivateKeyFromP12(sm2Data, p12Pwd);
            X509Certificate? cert = SmCertUtils.GetCertFromP12(sm2Data);

            //文档原创
            byte[] sourceBytes = Encoding.UTF8.GetBytes("Z000022725Z00002272021-02-04 10:47:30.88211637480324508820641");
            byte[] privateKey = SmCertUtils.GetPrivateKey(pv);
            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, cert, sourceBytes);

            bool isOk = SignatureUtils.Sm2Verify(sourceBytes, signBytes);
            Assert.IsTrue(isOk);
        }


        [TestMethod]
        public void Sm2SignWithSm2SignatureTest()
        {
            string privateKeyHex = "8a455cd2b5d8cbb164188f1aafa102ba7a381d97a5520c79a2a9fabf25f43e48";
            string source = "123456";
            byte[] privateKey = HexUtils.ToByteArray(privateKeyHex);
            byte[] content = Encoding.UTF8.GetBytes(source);
            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content, true);
            //to hex
            string sign = HexUtils.ToHexString(signBytes);
            Assert.IsNotNull(sign);
            Console.WriteLine("Sm2SignWithSm2SignatureTest->sign hex：" + sign);
            //to base64
            Console.WriteLine("Sm2SignWithSm2SignatureTest->sign Base64:" + Convert.ToBase64String(signBytes));
            string publicKeyHex = "048e2e2cff6c8ebfaaf8d9cb43c0afd62cc992833708e564678803d00d0983229fe4f4e75e0ba6b57b246d9b98fb19b11b17140ea251cef71d27dd76f5e88865e5";
            bool isOk = SignatureUtils.Sm2Verify(HexUtils.ToByteArray(publicKeyHex), content, signBytes, true);
            Assert.IsTrue(isOk);
        }

        [TestMethod]
        public void Sm2VerifyTest()
        {
            string source = "123456";
            string publicKeyHex = "04cd5d45fb73d90c8c1084b20195e450d0228f64b9a7bc480b845667aba7e6d09ed5aabb1c8ed28a2e5c5956db37d3c112eaea21614c599a577d6cef46d3a25256";

            byte[] publicKey = HexUtils.ToByteArray(publicKeyHex);
            byte[] content = Encoding.UTF8.GetBytes(source);
            //hex
            string signHex = "304402200ed5bdb7102a1b91ff86a8b39f7e9a3ed3967bc51f1640a60f64cd562f1afac702206eec6c52389b4e9c2ba3548a963abc91d8b8571138427d438bbd4ffb2fcf9f4f";
            bool isSuccess = SignatureUtils.Sm2Verify(publicKey, content, HexUtils.ToByteArray(signHex));
            Assert.AreEqual(true, isSuccess);

            //base64
            string signBase64 = "MEQCIA7VvbcQKhuR/4aos59+mj7TlnvFHxZApg9kzVYvGvrHAiBu7GxSOJtOnCujVIqWOryR2LhXEThCfUOLvU/7L8+fTw==";
            isSuccess = SignatureUtils.Sm2Verify(publicKey, content, Convert.FromBase64String(signBase64));
            Assert.AreEqual(true, isSuccess);
        }

        [TestMethod]
        public void Sm2VerifyWithCertTest()
        {
            string privateKeyHex = "8a455cd2b5d8cbb164188f1aafa102ba7a381d97a5520c79a2a9fabf25f43e48";
            string publicKeyHex = "048e2e2cff6c8ebfaaf8d9cb43c0afd62cc992833708e564678803d00d0983229fe4f4e75e0ba6b57b246d9b98fb19b11b17140ea251cef71d27dd76f5e88865e5";
            byte[] privateKey = HexUtils.ToByteArray(privateKeyHex);
            byte[] publicKey = HexUtils.ToByteArray(publicKeyHex);
            X509Certificate cert = SmCertUtils.MakeCert(privateKey, publicKey, "test1", "test2");
            string source = "123456";
            byte[] content = Encoding.UTF8.GetBytes(source);
            byte[] signBytes = SignatureUtils.Sm2Sign(privateKey, content, true);
            bool isOk = SignatureUtils.Sm2Verify(cert, content, signBytes, true);
            Assert.IsTrue(isOk);
        }
    }
}