using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace OpenSsl.Crypto.Utility.Tests
{
    [TestClass()]
    public class KeyExchangeUtilsTests
    {
        [TestMethod()]
        public void CreateParametersTest()
        {
            DhParams kp = KeyExchangeUtils.CreateParameters();
            Assert.IsNotNull(kp);
        }

        [TestMethod()]
        public void CreateDhKeyPairTest()
        {
            DhParams kp = KeyExchangeUtils.CreateParameters();
            Assert.IsNotNull(kp);
            CipherKeyPair keyPair = KeyExchangeUtils.CreateDhKeyPair(kp.P, kp.G);
            Assert.IsNotNull(keyPair);
        }

        [TestMethod()]
        public void CreateDHSecretTest()
        {
            DhParams kp = KeyExchangeUtils.CreateParameters();
            Assert.IsNotNull(kp);

            CipherKeyPair keyPair = KeyExchangeUtils.CreateDhKeyPair(kp.P, kp.G);
            Assert.IsNotNull(keyPair);

            string secret = KeyExchangeUtils.CreateSecret("DH", keyPair.Public, keyPair.Private);
            Assert.IsNotNull(secret);
        }

        [TestMethod()]
        public void CreateECDHSecretTest()
        {
            CipherKeyPair keyPair = KeyExchangeUtils.CreateEcDhKeyPair();
            Assert.IsNotNull(keyPair);

            string secret = KeyExchangeUtils.CreateSecret("ECDH", keyPair.Public, keyPair.Private);
            Assert.IsNotNull(secret);
        }

        [TestMethod()]
        public void CreateEcDhKeyPairTest()
        {
            CipherKeyPair keyPair = KeyExchangeUtils.CreateEcDhKeyPair();
            Assert.IsNotNull(keyPair);
        }

        [TestMethod]
        public void DHValidateTest()
        {
            int size = 256;
            DhParams parameters = KeyExchangeUtils.CreateParameters(size);

            CipherKeyPair partA = KeyExchangeUtils.CreateDhKeyPair(parameters.P, parameters.G);
            CipherKeyPair partB = KeyExchangeUtils.CreateDhKeyPair(parameters.P, parameters.G);
            Assert.AreNotEqual(partA.Public, partB.Public);
            Assert.AreNotEqual(partA.Private, partB.Private);

            string keyA = KeyExchangeUtils.CreateSecret("DH", partA.Public, partB.Private);
            string keyB = KeyExchangeUtils.CreateSecret("DH", partB.Public, partA.Private);
            Assert.AreEqual(keyA, keyB);
            Console.WriteLine("DH keyA={0},keyB={1}", keyA, keyB);
        }

        [TestMethod]
        public void DHKeyExchangeTest()
        {
            int size = 256;
            DhParams parameters = KeyExchangeUtils.CreateParameters(size);

            CipherKeyPair partA = KeyExchangeUtils.CreateDhKeyPair(parameters.P, parameters.G);
            CipherKeyPair partB = KeyExchangeUtils.CreateDhKeyPair(parameters.P, parameters.G);

            string key = KeyExchangeUtils.CreateSecret("DH", partA.Public, partB.Private);
            byte[] keyBytes = HexUtils.ToByteArray(key);

            string raw = Guid.NewGuid().ToString();
            byte[] cipb = CryptoUtils.AesEncrypt(keyBytes, raw, CipherMode.ECB, CipherPadding.PKCS1);
            string rw = CryptoUtils.AesDecrypt(keyBytes, cipb, CipherMode.ECB, CipherPadding.PKCS1);

            Assert.AreEqual(raw, rw);
        }

        [TestMethod]
        public void ECDHKeyExchangeTest()
        {
            CipherKeyPair partA = KeyExchangeUtils.CreateEcDhKeyPair();
            CipherKeyPair partB = KeyExchangeUtils.CreateEcDhKeyPair();

            string key = KeyExchangeUtils.CreateSecret("ECDH", partA.Public, partB.Private);
            byte[] keyBytes = HexUtils.ToByteArray(key);

            string raw = Guid.NewGuid().ToString();
            byte[] cipb = CryptoUtils.AesEncrypt(keyBytes, raw, CipherMode.ECB, CipherPadding.PKCS1);
            string rw = CryptoUtils.AesDecrypt(keyBytes, cipb, CipherMode.ECB, CipherPadding.PKCS1);

            Assert.AreEqual(raw, rw);
        }

        [TestMethod]
        public void ECDHKeyValidateTest()
        {
            CipherKeyPair partA = KeyExchangeUtils.CreateEcDhKeyPair();
            CipherKeyPair partB = KeyExchangeUtils.CreateEcDhKeyPair();
            Assert.AreNotEqual(partA.Public, partB.Public);
            Assert.AreNotEqual(partA.Private, partB.Private);

            string keyA = KeyExchangeUtils.CreateSecret("ECDH", partA.Public, partB.Private);
            string keyB = KeyExchangeUtils.CreateSecret("ECDH", partB.Public, partA.Private);
            Assert.AreEqual(keyA, keyB);
            Console.WriteLine("ECDH keyA={0},keyB={1}", keyA, keyB);
        }
    }
}