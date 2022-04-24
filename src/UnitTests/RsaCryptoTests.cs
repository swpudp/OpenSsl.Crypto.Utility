using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// RSA加密/解密测试
    /// </summary>
    [TestClass]
    public class RsaCryptoTests
    {
        /// <summary>
        /// RAS加密测试
        /// </summary>
        [TestMethod]
        public void EncryptUseKeyPairNonePaddingTest()
        {
            string content = "123456";
            var keyPair = RsaCertUtils.CreateCipherKeyPair();
            Console.WriteLine("publicKey:" + keyPair.Public);
            Console.WriteLine("privateKey:" + keyPair.Private);

            byte[] cipherBytes = CryptoUtils.RsaEncrypt(keyPair.Public, content, Encoding.UTF8, CipherMode.NONE, CipherPadding.NONE);
            //加密
            string cipher = Convert.ToBase64String(cipherBytes);
            Console.WriteLine("cipher:" + cipher);
            //解密
            string plainText = CryptoUtils.RsaDecrypt(keyPair.Private, Convert.FromBase64String(cipher), Encoding.UTF8, CipherMode.NONE, CipherPadding.NONE);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// RAS/Pkcs1Padding加密测试
        /// </summary>
        [TestMethod]
        public void EncryptUseKeyPairPkcs1PaddingTest()
        {
            string content = "123456";
            var keyPair = RsaCertUtils.CreateCipherKeyPair();
            Console.WriteLine("Public:" + keyPair.Public);
            Console.WriteLine("Private:" + keyPair.Private);
            //加密
            byte[] cipherBytes = CryptoUtils.RsaEncrypt(keyPair.Public, content, Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            string cipher = Convert.ToBase64String(cipherBytes);
            Console.WriteLine("cipherPublic:" + cipher);
            //解密
            string plainText = CryptoUtils.RsaDecrypt(keyPair.Private, Convert.FromBase64String(cipher), Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// RAS/ECB/Pkcs1Padding加密测试
        /// </summary>
        [TestMethod]
        public void EncryptUseKeyPairEcbPkcs1PaddingTest()
        {
            string content = "123456";
            var keyPair = RsaCertUtils.CreateCipherKeyPair();
            Console.WriteLine(keyPair.Public);
            Console.WriteLine(keyPair.Private);
            //加密
            byte[] cipherBytes = CryptoUtils.RsaEncrypt(keyPair.Public, content, Encoding.UTF8, CipherMode.ECB, CipherPadding.PKCS1);
            string cipher = Convert.ToBase64String(cipherBytes);
            Console.WriteLine(cipher);
            //解密
            string plainText = CryptoUtils.RsaDecrypt(keyPair.Private, Convert.FromBase64String(cipher), Encoding.UTF8, CipherMode.ECB, CipherPadding.PKCS1);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// 读取公钥测试
        /// </summary>
        [TestMethod]
        public void ReadPublicKeyTest()
        {
            string publicKeyPath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Tls", "public_key.pem");
            var publicKey = RsaCertUtils.ReadPublicKey(publicKeyPath);
            string expect = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            Assert.AreEqual(expect, publicKey);
        }

        /// <summary>
        /// 读取私钥测试
        /// </summary>
        [TestMethod]
        public void ReadPrivateKeyTest()
        {
            string privateKeyPath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Tls", "private_key.pem");
            var privateKey = RsaCertUtils.ReadPrivateKey(privateKeyPath);
            Assert.IsNotNull(privateKey);
            Console.WriteLine("privateKey:" + privateKey);
        }

        /// <summary>
        /// 获取私钥文件内容测试
        /// </summary>
        [TestMethod]
        public void CreatePemCipherKeyPairTest()
        {
            var keyPair = RsaCertUtils.CreatePemCipherKeyPair(2048);
            Console.WriteLine("CreatePemCipherKeyPairTest->keyPair.Private:");
            Console.WriteLine(keyPair.Private);
            Console.WriteLine("CreatePemCipherKeyPairTest->keyPair.Public:");
            Console.WriteLine(keyPair.Public);
            Assert.IsTrue(keyPair.Public.StartsWith("-----BEGIN PUBLIC KEY-----"));
            Assert.IsTrue(keyPair.Public.EndsWith("-----END PUBLIC KEY-----\r\n"));
            Assert.IsTrue(keyPair.Private.StartsWith("-----BEGIN RSA PRIVATE KEY-----"));
            Assert.IsTrue(keyPair.Private.EndsWith("-----END RSA PRIVATE KEY-----\r\n"));
        }

        /// <summary>
        /// RAS加密测试
        /// </summary>
        [TestMethod]
        public void EncryptUsePemTest()
        {
            string content = "123456";
            //加密
            string publicKeyPath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Tls", "public_key.pem");
            var publicKey = RsaCertUtils.ReadPublicKey(publicKeyPath);
            byte[] cipherBytes = CryptoUtils.RsaEncrypt(publicKey, content, Encoding.UTF8, CipherMode.NONE, CipherPadding.NONE);
            string cipher = Convert.ToBase64String(cipherBytes);

            //解密
            string privateKeyPath = Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Tls", "private_key.pem");
            var privateKey = RsaCertUtils.ReadPrivateKey(privateKeyPath);
            string plainText = CryptoUtils.RsaDecrypt(privateKey, Convert.FromBase64String(cipher), Encoding.UTF8, CipherMode.NONE, CipherPadding.NONE);
            Assert.AreEqual(content, plainText);
        }

        /// <summary>
        /// 证书文件目录
        /// </summary>
        private const string CaCerFileDir = "CACert";

        /// <summary>
        /// 证书文件路径
        /// </summary>
        private const string CaCerFilePath = "CACert/sk-soc.cer";

        /// <summary>
        /// 私钥文件路径
        /// </summary>
        private const string CaKeyFilePath = "CACert/sk-soc.key";

        /// <summary>
        /// 生成ca证书测试
        /// </summary>
        [TestMethod]
        [Priority(1)]
        public void GenerateCertTest()
        {
            if (!System.IO.Directory.Exists(CaCerFileDir))
            {
                Directory.CreateDirectory(CaCerFileDir);
            }

            var validFrom = DateTime.Today.AddDays(-1);
            var validTo = DateTime.Today.AddYears(10);
            string cert = RsaCertUtils.GenerateBySelf(new[] {"sk-soc"}, 1024, validFrom, validTo, out string caPrivateCert);
            File.WriteAllText(CaKeyFilePath, caPrivateCert);
            File.WriteAllText(CaCerFilePath, cert);
        }

        /// <summary>
        /// 从CA证书生成pfx证书
        /// </summary>
        [TestMethod]
        [Priority(0)]
        public void GenerateFromCaTest()
        {
            var domains = GetDomains("test").Distinct().ToList();
            var validFrom = DateTime.Today.AddDays(-1);
            var validTo = DateTime.Today.AddYears(1);
            byte[] certBytes = RsaCertUtils.GenerateFromCa(domains, 1024, validFrom, validTo, CaCerFilePath, CaKeyFilePath);
            Assert.IsNotNull(certBytes);
        }

        [TestMethod]
        public void ReadPemContentTest()
        {
            var pemPriKey = RsaCertUtils.ReadPrivateKey(@"Tls/private_key_cmb.pem");
            string privateKey = "MIIEowIBAAKCAQEAwN7xTseqQs1pNA/+gTgXRqcxCYfkxDTsckfqf3O2ndsvJS5T8Fb0oHTyjy0HjrKLASWWUKfhQGXPHbo1FQd+0TyHxSza55+HtXquUq7QsAITHCu3U7aslvC7xe6/2E7nhu1TausF1nSyB1o4xVEjZyjrdQpTID0JvG8BtA5Yem9YDBCMZHBxvarQHVqdBsqo2G3M09qeUDbY3DuBgdiVAw0ApIM8mKGj4jsWmRSnypuxl40BjWAr6Xgk44MpSGHndhiFXGvfMRRYEd8Z30w32QlB+Gjk8rQwXnvxG8YCBPYqXVkqwld81bHFFz5zHQ0qekPhD8RrFimPn+RaD9VNfwIDAQABAoIBAQCxUUZQw0hJOkgqUToO2t6rWjK/LGyp5m4rcuqoWl3eKxDhAgKxx4AHtPz7nM6B5qvdVg0oAfAZIICWOAdtWgLBowC/yklHAWfm9O8nnQjHiGDBWX+mOx/ZdWFsy98cow5BAhfbCE/Jpme2UsA2yC3gPcKbS+64iOVWlEfgnf/CLte/dE0eAMfsp5wXpwv3ygA4wtyd2X2P+y6s+WYBKSvNMS08W4dsxwU9Q3AG3hS0Uab09qIPNS8tEMZ2L1tl0/VvkrAYjayM1CcKCrSnwtH6eJVi4WQxL1K3QxyxDKucsOlqSHg++4VMpGZNpvstn3IsY3PyCgfsODvHaoygvDBhAoGBAPxxdcI9stK9bIGSms0FqbVXYj8WmAjE/M9B7ECToWRQg65Gf8MYPyUSkY2mbDHwf+yPsUb5Oli+a2GW8BwmJWeXEIy0lQxa1TS2b7CN6XJtZVnjEgiZd7bXy/j69r/C4CMlfbrRWnUGftKr/U7ynaGs10/bISeW12E7WdLV5+kDAoGBAMOWnEzAFMPFzG9p/GtYpWU5jMNSiakzfm6n9Nwr7dFGnLhVGtO6act1bm/WB26NAgIEArhcitoKrI346nfkoZLXBpzzyJgFx4r31d1RN9Vsrt6AEywlwnLwHk2HXtCwmqrehZ4I741S2rHlaT8ifNwLyjW2sbw9QnpC3RL7R3rVAoGAOI/Dbs4cLxO6KB4NCTrnl3YI0VHiprRcYKPIp39sfel8V6P8JF5eZ5QNgMt1GotkXkCj298jr5aawLbs/aGeZ+N1FdGwQ6BmfPUTeV+SmszgFI/IDp00MYeQcCzq9HRZfAZ+cUlPF0FpURKwIuxBXWQ4qe/TMeeeQm7l5VOALrkCgYAljLa5LW9PHpxfD3P8j+pBAsl5flEbgN1XFTu3QV/I+8t+wCgEWheRjhwDsI2AteWayXZUOsAVmFMEdrNdDTHP5SRJ4auzM/jZPzd54+vaN6Fi6ifEJAOu2VaX/9M+MYmgIFR6wLBs62k9GhQYoOBjxoetxENfJkuq+UdEK6XPeQKBgFvf+SUrg7hFpRRyCq+DehdMQk1TJnEPTNLOalfrA/319KA8LGa0Q+ay5c2mDc9F//yAJEAT1WTEqHnvKBQvjofFAGRntoCT8anAnskSytwwpltKqDcpoKx/hVK+eVL47wuFroCBLGj0Zm3I7S+saGGmVllEky4jceE7IMTN7i6W";
            string key = RsaCertUtils.GetPrivateKeyFromPemContent(privateKey, false);
            Console.WriteLine(key);
            Assert.IsNotNull(key);
            Assert.AreEqual(pemPriKey, key);

            var pemPubKey = RsaCertUtils.ReadPublicKey(@"Tls/public_key.pem");
            string pemPubKeyContent = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMsyV0GGupSENjIZqsIittuRIX5ELI8Mhw82SLfHBsRJ2Sdbcb9kVgeBbhPKs/pT5aqjBjyiNC8jXgxwbFKgs50nEv7hANpTRXvwcn1j6Rg9muPV+xnbjg2ygudOzaXbCjENHRs4sD1jkYpSG+avpZYWI6KTn0eq0WzqNtMMKT6QIDAQAB";
            string pubKey = RsaCertUtils.GetPublicKeyFromPemContent(pemPubKeyContent);
            Assert.AreEqual(pemPubKey, pubKey);
        }

        [TestMethod]
        public void EncryptAndDecryptFromByReadPemContentTest()
        {
            string privateKeyContent = "MIIEowIBAAKCAQEAwN7xTseqQs1pNA/+gTgXRqcxCYfkxDTsckfqf3O2ndsvJS5T8Fb0oHTyjy0HjrKLASWWUKfhQGXPHbo1FQd+0TyHxSza55+HtXquUq7QsAITHCu3U7aslvC7xe6/2E7nhu1TausF1nSyB1o4xVEjZyjrdQpTID0JvG8BtA5Yem9YDBCMZHBxvarQHVqdBsqo2G3M09qeUDbY3DuBgdiVAw0ApIM8mKGj4jsWmRSnypuxl40BjWAr6Xgk44MpSGHndhiFXGvfMRRYEd8Z30w32QlB+Gjk8rQwXnvxG8YCBPYqXVkqwld81bHFFz5zHQ0qekPhD8RrFimPn+RaD9VNfwIDAQABAoIBAQCxUUZQw0hJOkgqUToO2t6rWjK/LGyp5m4rcuqoWl3eKxDhAgKxx4AHtPz7nM6B5qvdVg0oAfAZIICWOAdtWgLBowC/yklHAWfm9O8nnQjHiGDBWX+mOx/ZdWFsy98cow5BAhfbCE/Jpme2UsA2yC3gPcKbS+64iOVWlEfgnf/CLte/dE0eAMfsp5wXpwv3ygA4wtyd2X2P+y6s+WYBKSvNMS08W4dsxwU9Q3AG3hS0Uab09qIPNS8tEMZ2L1tl0/VvkrAYjayM1CcKCrSnwtH6eJVi4WQxL1K3QxyxDKucsOlqSHg++4VMpGZNpvstn3IsY3PyCgfsODvHaoygvDBhAoGBAPxxdcI9stK9bIGSms0FqbVXYj8WmAjE/M9B7ECToWRQg65Gf8MYPyUSkY2mbDHwf+yPsUb5Oli+a2GW8BwmJWeXEIy0lQxa1TS2b7CN6XJtZVnjEgiZd7bXy/j69r/C4CMlfbrRWnUGftKr/U7ynaGs10/bISeW12E7WdLV5+kDAoGBAMOWnEzAFMPFzG9p/GtYpWU5jMNSiakzfm6n9Nwr7dFGnLhVGtO6act1bm/WB26NAgIEArhcitoKrI346nfkoZLXBpzzyJgFx4r31d1RN9Vsrt6AEywlwnLwHk2HXtCwmqrehZ4I741S2rHlaT8ifNwLyjW2sbw9QnpC3RL7R3rVAoGAOI/Dbs4cLxO6KB4NCTrnl3YI0VHiprRcYKPIp39sfel8V6P8JF5eZ5QNgMt1GotkXkCj298jr5aawLbs/aGeZ+N1FdGwQ6BmfPUTeV+SmszgFI/IDp00MYeQcCzq9HRZfAZ+cUlPF0FpURKwIuxBXWQ4qe/TMeeeQm7l5VOALrkCgYAljLa5LW9PHpxfD3P8j+pBAsl5flEbgN1XFTu3QV/I+8t+wCgEWheRjhwDsI2AteWayXZUOsAVmFMEdrNdDTHP5SRJ4auzM/jZPzd54+vaN6Fi6ifEJAOu2VaX/9M+MYmgIFR6wLBs62k9GhQYoOBjxoetxENfJkuq+UdEK6XPeQKBgFvf+SUrg7hFpRRyCq+DehdMQk1TJnEPTNLOalfrA/319KA8LGa0Q+ay5c2mDc9F//yAJEAT1WTEqHnvKBQvjofFAGRntoCT8anAnskSytwwpltKqDcpoKx/hVK+eVL47wuFroCBLGj0Zm3I7S+saGGmVllEky4jceE7IMTN7i6W";
            string privateKey = RsaCertUtils.GetPrivateKeyFromPemContent(privateKeyContent, false);
            Assert.IsNotNull(privateKey);
            string publicKey = RsaCertUtils.GetPublicKeyFromPrivatePemContent(privateKeyContent);
            Assert.IsNotNull(publicKey);

            string content = Guid.NewGuid().ToString();
            byte[] cipherBytes = CryptoUtils.RsaEncrypt(publicKey, content, Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            string cipherBase64 = Convert.ToBase64String(cipherBytes);
            string plainText = CryptoUtils.RsaDecrypt(privateKey, Convert.FromBase64String(cipherBase64), Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            Assert.AreEqual(content, plainText);
        }

        [TestMethod]
        public void ReadPemContentOnlyPrivateTest()
        {
            var pemPriKey = RsaCertUtils.ReadPrivateKey(@"Tls/private_key_cmb.pem");
            string onlyPrivateKeyPemContent = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDA3vFOx6pCzWk0D/6BOBdGpzEJh+TENOxyR+p/c7ad2y8lLlPwVvSgdPKPLQeOsosBJZZQp+FAZc8dujUVB37RPIfFLNrnn4e1eq5SrtCwAhMcK7dTtqyW8LvF7r/YTueG7VNq6wXWdLIHWjjFUSNnKOt1ClMgPQm8bwG0Dlh6b1gMEIxkcHG9qtAdWp0GyqjYbczT2p5QNtjcO4GB2JUDDQCkgzyYoaPiOxaZFKfKm7GXjQGNYCvpeCTjgylIYed2GIVca98xFFgR3xnfTDfZCUH4aOTytDBee/EbxgIE9ipdWSrCV3zVscUXPnMdDSp6Q+EPxGsWKY+f5FoP1U1/AgMBAAECggEBALFRRlDDSEk6SCpROg7a3qtaMr8sbKnmbity6qhaXd4rEOECArHHgAe0/PuczoHmq91WDSgB8BkggJY4B21aAsGjAL/KSUcBZ+b07yedCMeIYMFZf6Y7H9l1YWzL3xyjDkECF9sIT8mmZ7ZSwDbILeA9wptL7riI5VaUR+Cd/8Iu1790TR4Ax+ynnBenC/fKADjC3J3ZfY/7Lqz5ZgEpK80xLTxbh2zHBT1DcAbeFLRRpvT2og81Ly0QxnYvW2XT9W+SsBiNrIzUJwoKtKfC0fp4lWLhZDEvUrdDHLEMq5yw6WpIeD77hUykZk2m+y2fcixjc/IKB+w4O8dqjKC8MGECgYEA/HF1wj2y0r1sgZKazQWptVdiPxaYCMT8z0HsQJOhZFCDrkZ/wxg/JRKRjaZsMfB/7I+xRvk6WL5rYZbwHCYlZ5cQjLSVDFrVNLZvsI3pcm1lWeMSCJl3ttfL+Pr2v8LgIyV9utFadQZ+0qv9TvKdoazXT9shJ5bXYTtZ0tXn6QMCgYEAw5acTMAUw8XMb2n8a1ilZTmMw1KJqTN+bqf03Cvt0UacuFUa07ppy3Vub9YHbo0CAgQCuFyK2gqsjfjqd+ShktcGnPPImAXHivfV3VE31Wyu3oATLCXCcvAeTYde0LCaqt6FngjvjVLaseVpPyJ83AvKNbaxvD1CekLdEvtHetUCgYA4j8NuzhwvE7ooHg0JOueXdgjRUeKmtFxgo8inf2x96XxXo/wkXl5nlA2Ay3Uai2ReQKPb3yOvlprAtuz9oZ5n43UV0bBDoGZ89RN5X5KazOAUj8gOnTQxh5BwLOr0dFl8Bn5xSU8XQWlRErAi7EFdZDip79Mx555CbuXlU4AuuQKBgCWMtrktb08enF8Pc/yP6kECyXl+URuA3VcVO7dBX8j7y37AKARaF5GOHAOwjYC15ZrJdlQ6wBWYUwR2s10NMc/lJEnhq7Mz+Nk/N3nj69o3oWLqJ8QkA67ZVpf/0z4xiaAgVHrAsGzraT0aFBig4GPGh63EQ18mS6r5R0Qrpc95AoGAW9/5JSuDuEWlFHIKr4N6F0xCTVMmcQ9M0s5qV+sD/fX0oDwsZrRD5rLlzaYNz0X//IAkQBPVZMSoee8oFC+Oh8UAZGe2gJPxqcCeyRLK3DCmW0qoNymgrH+FUr55UvjvC4WugIEsaPRmbcjtL6xoYaZWWUSTLiNx4TsgxM3uLpY=";
            string priKey = RsaCertUtils.GetPrivateKeyFromPemContent(onlyPrivateKeyPemContent, true);
            Assert.AreEqual(pemPriKey, priKey);
            Assert.ThrowsException<InvalidCastException>(() => RsaCertUtils.GetPrivateKeyFromPemContent(onlyPrivateKeyPemContent, false));
            Assert.ThrowsException<InvalidCastException>(() => RsaCertUtils.GetPublicKeyFromPrivatePemContent(onlyPrivateKeyPemContent));
        }

        [TestMethod]
        public void ReadPemPrivateKeyTest()
        {
            string privateKeyValue = "MIIEowIBAAKCAQEAwN7xTseqQs1pNA/+gTgXRqcxCYfkxDTsckfqf3O2ndsvJS5T8Fb0oHTyjy0HjrKLASWWUKfhQGXPHbo1FQd+0TyHxSza55+HtXquUq7QsAITHCu3U7aslvC7xe6/2E7nhu1TausF1nSyB1o4xVEjZyjrdQpTID0JvG8BtA5Yem9YDBCMZHBxvarQHVqdBsqo2G3M09qeUDbY3DuBgdiVAw0ApIM8mKGj4jsWmRSnypuxl40BjWAr6Xgk44MpSGHndhiFXGvfMRRYEd8Z30w32QlB+Gjk8rQwXnvxG8YCBPYqXVkqwld81bHFFz5zHQ0qekPhD8RrFimPn+RaD9VNfwIDAQABAoIBAQCxUUZQw0hJOkgqUToO2t6rWjK/LGyp5m4rcuqoWl3eKxDhAgKxx4AHtPz7nM6B5qvdVg0oAfAZIICWOAdtWgLBowC/yklHAWfm9O8nnQjHiGDBWX+mOx/ZdWFsy98cow5BAhfbCE/Jpme2UsA2yC3gPcKbS+64iOVWlEfgnf/CLte/dE0eAMfsp5wXpwv3ygA4wtyd2X2P+y6s+WYBKSvNMS08W4dsxwU9Q3AG3hS0Uab09qIPNS8tEMZ2L1tl0/VvkrAYjayM1CcKCrSnwtH6eJVi4WQxL1K3QxyxDKucsOlqSHg++4VMpGZNpvstn3IsY3PyCgfsODvHaoygvDBhAoGBAPxxdcI9stK9bIGSms0FqbVXYj8WmAjE/M9B7ECToWRQg65Gf8MYPyUSkY2mbDHwf+yPsUb5Oli+a2GW8BwmJWeXEIy0lQxa1TS2b7CN6XJtZVnjEgiZd7bXy/j69r/C4CMlfbrRWnUGftKr/U7ynaGs10/bISeW12E7WdLV5+kDAoGBAMOWnEzAFMPFzG9p/GtYpWU5jMNSiakzfm6n9Nwr7dFGnLhVGtO6act1bm/WB26NAgIEArhcitoKrI346nfkoZLXBpzzyJgFx4r31d1RN9Vsrt6AEywlwnLwHk2HXtCwmqrehZ4I741S2rHlaT8ifNwLyjW2sbw9QnpC3RL7R3rVAoGAOI/Dbs4cLxO6KB4NCTrnl3YI0VHiprRcYKPIp39sfel8V6P8JF5eZ5QNgMt1GotkXkCj298jr5aawLbs/aGeZ+N1FdGwQ6BmfPUTeV+SmszgFI/IDp00MYeQcCzq9HRZfAZ+cUlPF0FpURKwIuxBXWQ4qe/TMeeeQm7l5VOALrkCgYAljLa5LW9PHpxfD3P8j+pBAsl5flEbgN1XFTu3QV/I+8t+wCgEWheRjhwDsI2AteWayXZUOsAVmFMEdrNdDTHP5SRJ4auzM/jZPzd54+vaN6Fi6ifEJAOu2VaX/9M+MYmgIFR6wLBs62k9GhQYoOBjxoetxENfJkuq+UdEK6XPeQKBgFvf+SUrg7hFpRRyCq+DehdMQk1TJnEPTNLOalfrA/319KA8LGa0Q+ay5c2mDc9F//yAJEAT1WTEqHnvKBQvjofFAGRntoCT8anAnskSytwwpltKqDcpoKx/hVK+eVL47wuFroCBLGj0Zm3I7S+saGGmVllEky4jceE7IMTN7i6W";
            string privateKeyBase64 = RsaCertUtils.GetPrivateKeyFromPemContent(privateKeyValue, false);
            byte[] privateKey = Convert.FromBase64String(privateKeyBase64);
            string valueStr = "{\"request\":{\"body\":{\"ntbusmody\":[],\"ntecocsax1\":[{\"brneac\":\"755936046310201\",\"cstnam\":\"中建电子商务有限责任公司\",\"intacc\":\"755936046310903\",\"intflg\":\"N\",\"ntfurl\":\"http://118.113.15.111:8081/bank/cmb/transaction\",\"rcvchk\":\"Y\",\"shracc\":\"755936046310903\",\"shrnam\":\"银企直连专用测试企业279\",\"yurref\":\"20211126163904SSSSystem.Random\"}]},\"head\":{\"funcode\":\"NTECOCSA\",\"reqid\":\"20211126163904SSSSystem.Random\",\"userid\":\"N002986845\"},\"signature\":{\"sigdat\":\"\",\"sigtim\":\"20211126163904\"}},\"signature\":{\"sigdat\":\"__signature_sigdat__\",\"sigtim\":\"20211126165559\"}}";
            byte[] valueStrBytes = Encoding.UTF8.GetBytes(valueStr);
            string sign = "Xvf89tMK65/336cRiuRcYWHU4igzF2jiuvtOUvoBwq8Ztt5HReF8GgOdOXVW6orE/hoqihL7QqUYD2RjnmxSj6lfNR5VOJogdKBE/4sTq+fjgEcZiud82YBaMetozLTyxuwHIYAiIAaO2ZmrPP1Puwfh2fEva7/ySeX182a+FRxhbtN6Xnw7echGAmgtAO0jOCawuaKitP6XV9eb2w1s+T56GGXvVDYtUIx9Y3OE6T0FA6VUR37cBggwofKiXKTR4pSQSW5udw4K361HNPGaTbcaowUTN1hrYSWx6xroplr7LrU5hGwjczTOfGFvPPGQ8Aix3EBgwpY2+rXf+bGDDA==";
            string actualSign = Convert.ToBase64String(SignatureUtils.RsaSign(privateKey, valueStrBytes, RsaSignerAlgorithm.SHA256withRSA));
            Assert.AreEqual(sign, actualSign);
        }

        /// <summary>
        /// 获取域名
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        private static IEnumerable<string> GetDomains(string domain)
        {
            if (!string.IsNullOrEmpty(domain))
            {
                yield return domain;
                yield break;
            }

            yield return Environment.MachineName;
            foreach (var address in LocalMachine.GetAllIPv4Addresses())
            {
                yield return address.ToString();
            }
        }

        [TestMethod]
        public void ECIESTest()
        {
            //加密公钥
            string serverPublicKey = "MFUwEwYHKoZIzj0CAQYIKoZIzj0DAQQDPgAEdWm4qAYlcpz/3irjz4KK5UsK+Eg4CHjPlQrLiJEKJifkC760U8mtLjY9Mb32TeaKPN8ZVSxu86Eovb6r";
            string data = "123456";
            Assert.ThrowsException<NotImplementedException>(() => ECIESEncrypting(data, serverPublicKey, Encoding.UTF8));
        }

        /// <summary>
        /// ECC公钥加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="servicePublicKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        private static string ECIESEncrypting(string data, string servicePublicKey, Encoding encoding)
        {
            Org.BouncyCastle.Asn1.Asn1Object pubKeyObj = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(Convert.FromBase64String(servicePublicKey));
            Org.BouncyCastle.Crypto.AsymmetricKeyParameter pubKey = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance(pubKeyObj));
            Org.BouncyCastle.Crypto.IBufferedCipher c1 = Org.BouncyCastle.Security.CipherUtilities.GetCipher("ECIES");
            c1.Init(false, pubKey);
            byte[] bytesToDecrypt = encoding.GetBytes(data);
            byte[] result = c1.DoFinal(bytesToDecrypt, 0, bytesToDecrypt.Length);
            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// pfx加密解密测试
        /// </summary>
        /// <returns></returns>
        [TestMethod]
        public void EncryptAndDecryptWithPfxTest()
        {
            var privateKey = RsaCertUtils.GetPrivateKeyFromPfx(@"Tls/TEST.pfx", "mcl1024#");
            string expectedKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgqqVenYjd6x5Og2lT5l8PU0VyPShCfGZbY6Ld/YiVog7tC7+BeIQPm2DWEJ1EQ5haOqBReH3I2d998Qn3s1Y38SUQXBx1MnKgOkkWZ29Im6TFCOyB2TguyRUfp8NgYcH8+4V4lw+ch4du8fuk1AHTAxug72Lbu5e/5LoAJL3x8KW5vMkIkO1ffnh9VIgBk2l0CjRq4/xTjtrZidQGbPQTf2vc12LuVF4xs4kIIw6DZSni1nYJtwTRhjOLbAuqJGR2T3T3mA0sFcsGa3WhEwIIiQZ4eX61fb2dVpVCAohKV7qWKZGkf37Y1hKXpSb9xK93D8teFTJ1qDdwy2gkjDhPAgMBAAECggEBAJhAHWWDs2dYnueX7//plrtXFcAj5Drc18JSsMvcrcneQHaxY1C1e6+udh1ksSM3SvB2DeYmYEws6nTWLbPk5hctFQpjvzPwEl9z3D621eXgWEu/ISALUApF0xakS6jR+ppZXynfPJQAen7QIL8ZiIEFuPDQ6MWBB1R40ym/p5/UAUfcddFM9UGxyEULc/OyFUv3XY+mfTfDChmXUlijXT5JUnikXOwM92AJBMzGA+9/yz8B+d0nfVCZZf/i9Ji+UzpMU7AyX1/CPM3qxfM0MwaSeVvemyLwCMWITbRN3vghNAfzJOCSbK1rqhY25UIGXPGNv1jFymKopi+emej5JEECgYEA4PL23eLEfHwARRLB86wM0KeQvijq5FnpcqnnWfc2IcSpJ9zaLpz0cOpeJ6uqwMjRpAxNy/MtIYpfel0trQ0gwNgXMOwHf6AS/UikQRMnWaRUxNV3wEDLZx6ak6ekPBbeCZlF5i+40ERDNqAGbEPMvRMr6oJ9LHZ2lcQ+5ymidhsCgYEAttgg2HV+D4vYHvFEniorUAbTDdLj1iCfsb0RIZUcJuMTAYsXM0LKhvarmFfGjhO7BJLHFg7h5KEvAaAszq/MjSANRazlVqGrj5RDDP2J43ETUA3zgITPLWpy+2JkSTVatXfMPHkyqOiySc5DTZGn4hEj0SJGdVuugwEdbmIE+d0CgYEAzxqicrL/V+UKko2sh93Vhp1fw9QEPu0Q44LN/6R88CYR3yOUtOnIm9ULjtacRRYe/Txeu/FNkd3F/fCfxv2ZNDM/VslYNgZ4tT0WDNvHlN6ZNQecUyLUokIo6tyjdrdPAeNd2YoCS60tfLNkdnUNoN5vxl8RQ8hlcYnWqBlK/BUCgYEAlJ9ze19tm4dpoiUtSH8we7lAXvE4HzqfdCMhxLFmk7lqHowHzLQS2cexzYAzthMVpm8EgsqQFX5rLiAbq9m8JE6UWzlhpZx+TpQOOIXySj0EnMLqVmId4WWwluPwbo1+8Riym8lMQ336RgHyNSAbXafe/ESnDwf5/ySt3qawMsUCgYAVRo3JZq26ldzZgeYH4rQatplQPIcqoigkFJ9XuWQDMl1/hilLp7xOAuThaU2U0fhM9rgL1jR2BKYwkip2y9j+EmtKD3NdwWTOhmgyHBly7UQjP9sMffxZ7RbcjwyCDdFi72D0/dT2jO/8Hxuk91vswglO+LjhY5wRFY6PVfu8aw==";
            Assert.AreEqual(expectedKey, privateKey);

            var reqJson = "8A05EAE2-AC79-4EBA-9D28-B98E1EFF3B86";
            string reqJsonHex = DigestUtils.Sha256(reqJson, Encoding.UTF8);
            Assert.AreEqual("ccbee7515574b9084cfce8f397aedec855c1359cf4a7aba6649a080883efb7b0", reqJsonHex);

            var publicKey = RsaCertUtils.GetPublicKeyFromPfx(@"Tls/TEST.pfx", "mcl1024#");
            string cipher = Convert.ToBase64String(CryptoUtils.RsaEncrypt(publicKey, reqJsonHex, Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1));
            string actualReqJsonSign = CryptoUtils.RsaDecrypt(privateKey, Convert.FromBase64String(cipher), Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            Assert.AreEqual(reqJsonHex, actualReqJsonSign);
        }

        /// <summary>
        /// hex加密解密测试
        /// </summary>
        [TestMethod]
        public void EncryptAndDecryptWithHexTest()
        {
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO9ZxSM9SRCiyybIVvBYOXWDJtEieakJS4b7Qtt1jyPJliAICPbl0zNrvuhK8onC/y7q/S+Oq5Y8pbezC9Uglu0gqvgBj0UaCnQmXNZdkotefnJvdTZI6tgbCaPCxW9sXQJlHPjQSHR2B+dKRONPbdjYWACUwYERWGYzC/q0Y1uRAgMBAAECgYAPzG9Ilq8qc8cQsxuYogd/kV3FYyRVpdaVkniExNs4Y6zO8MjVXIaBd+SyL4mX0fEHF0gJVL5QXIYcZys/m6GVOlVCJPjr9AtcinHIpY6Yh2Zes4DWKayc0dQ9b3bB9ghWv/M8cIeJG8ac8My92Rf9+BXoCUEgC6uzBlC0JAxD0wJBAPuSYQclvYpW7UQWhZxEeH1ugeeXTsdKDm0PowjPnOggWVYJrdfD/G8Ei/g4AZptfw1fbploNLXsKs/w2zWyWv8CQQDzkFIehH//jSTf6HOcfa2uxpIoM39XF2c/gULlhkiXffAvau8jZ3uHtw/NjoPgyKjF4QoMFkeV5a+f1wy11RlvAkEA1l0w2IpMLClOHAqk5zdhBGC5yMGhmyd7i2sbnVJrfVCzTyEIRSb3XxIcwvHWS+SpspdzAr1MzQfkozO1VtgXuQJADKlxC3MZ8GAXDajY8ca6074w9PQQZ6eoz21Z2/LKLU33wY9OlUmY62pB4Q7KnlHwLDFRw2UZHZrOMYINgBpu8wJAQa/C7S/zKNIdqLNBSckJbH+W7zDFBSevGcPB1VesWjZ5wJcuJa6iMwXAq/ci2bOlMsZSbN0bnsEb+mWqQ21L5g==";
            string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDvWcUjPUkQossmyFbwWDl1gybRInmpCUuG+0LbdY8jyZYgCAj25dMza77oSvKJwv8u6v0vjquWPKW3swvVIJbtIKr4AY9FGgp0JlzWXZKLXn5yb3U2SOrYGwmjwsVvbF0CZRz40Eh0dgfnSkTjT23Y2FgAlMGBEVhmMwv6tGNbkQIDAQAB";
            string content = Guid.NewGuid().ToString();
            string cipher = HexUtils.ToHexString(CryptoUtils.RsaEncrypt(publicKey, content, Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1));
            string expected = CryptoUtils.RsaDecrypt(privateKey, HexUtils.ToByteArray(cipher), Encoding.UTF8, CipherMode.NONE, CipherPadding.PKCS1);
            Assert.AreEqual(content, expected);
        }

        /// <summary>
        /// 加密解密测试
        /// </summary>
        [TestMethod]
        public void EncryptAndDecryptWithBytesTest()
        {
            string privateKeyBase64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAO9ZxSM9SRCiyybIVvBYOXWDJtEieakJS4b7Qtt1jyPJliAICPbl0zNrvuhK8onC/y7q/S+Oq5Y8pbezC9Uglu0gqvgBj0UaCnQmXNZdkotefnJvdTZI6tgbCaPCxW9sXQJlHPjQSHR2B+dKRONPbdjYWACUwYERWGYzC/q0Y1uRAgMBAAECgYAPzG9Ilq8qc8cQsxuYogd/kV3FYyRVpdaVkniExNs4Y6zO8MjVXIaBd+SyL4mX0fEHF0gJVL5QXIYcZys/m6GVOlVCJPjr9AtcinHIpY6Yh2Zes4DWKayc0dQ9b3bB9ghWv/M8cIeJG8ac8My92Rf9+BXoCUEgC6uzBlC0JAxD0wJBAPuSYQclvYpW7UQWhZxEeH1ugeeXTsdKDm0PowjPnOggWVYJrdfD/G8Ei/g4AZptfw1fbploNLXsKs/w2zWyWv8CQQDzkFIehH//jSTf6HOcfa2uxpIoM39XF2c/gULlhkiXffAvau8jZ3uHtw/NjoPgyKjF4QoMFkeV5a+f1wy11RlvAkEA1l0w2IpMLClOHAqk5zdhBGC5yMGhmyd7i2sbnVJrfVCzTyEIRSb3XxIcwvHWS+SpspdzAr1MzQfkozO1VtgXuQJADKlxC3MZ8GAXDajY8ca6074w9PQQZ6eoz21Z2/LKLU33wY9OlUmY62pB4Q7KnlHwLDFRw2UZHZrOMYINgBpu8wJAQa/C7S/zKNIdqLNBSckJbH+W7zDFBSevGcPB1VesWjZ5wJcuJa6iMwXAq/ci2bOlMsZSbN0bnsEb+mWqQ21L5g==";
            string publicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDvWcUjPUkQossmyFbwWDl1gybRInmpCUuG+0LbdY8jyZYgCAj25dMza77oSvKJwv8u6v0vjquWPKW3swvVIJbtIKr4AY9FGgp0JlzWXZKLXn5yb3U2SOrYGwmjwsVvbF0CZRz40Eh0dgfnSkTjT23Y2FgAlMGBEVhmMwv6tGNbkQIDAQAB";
            byte[] content = Guid.NewGuid().ToByteArray();
            byte[] publicKey = Convert.FromBase64String(publicKeyBase64);
            byte[] privateKey = Convert.FromBase64String(privateKeyBase64);

            byte[] cipherBytes = CryptoUtils.RsaEncrypt(publicKey, (content), CipherMode.NONE, CipherPadding.PKCS1);
            string cipher = HexUtils.ToHexString(cipherBytes);

            byte[] cipherBytes1 = HexUtils.ToByteArray(cipher);
            Assert.IsTrue(ArrayEquals(cipherBytes, cipherBytes1));
            byte[] expected = CryptoUtils.RsaDecrypt(privateKey, cipherBytes, CipherMode.NONE, CipherPadding.PKCS1);
            Assert.IsTrue(ArrayEquals(content, expected));
        }

        private static bool ArrayEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}