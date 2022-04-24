using System;
using System.Text;
using OpenSsl.Crypto.Utility.Internal;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 国密额外辅助工具
    /// </summary>
    public static class SmCertUtils
    {
        /// <summary>
        /// 生成SM2公私钥对
        /// </summary>
        /// <returns></returns>
        private static AsymmetricCipherKeyPair CreateKeyPairInternal()
        {
            //1.创建密钥生成器
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();

            //2.初始化生成器,带上随机数
            keyPairGenerator.Init(new ECKeyGenerationParameters(SmParameters.DomainParameters, new SecureRandom()));

            //3.生成密钥对
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.GenerateKeyPair();
            return asymmetricCipherKeyPair;
        }

        /// <summary>
        /// 生成密钥对（均为十六进制字符串）
        /// </summary>
        /// <param name="compressedPubKey">是否压缩公钥 默认压缩</param>
        /// <remarks>公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04</remarks>
        /// <returns>密钥对十六进制字符串</returns>
        public static CipherKeyPair GenerateKeyPair(bool compressedPubKey = true)
        {
            AsymmetricCipherKeyPair cipherKeyPair = CreateKeyPairInternal();
            //提取公钥点
            ECPoint ecPoint = ((ECPublicKeyParameters)cipherKeyPair.Public).Q;
            //公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
            string publicKey = Hex.ToHexString(ecPoint.GetEncoded(compressedPubKey));
            BigInteger privateKey = ((ECPrivateKeyParameters)cipherKeyPair.Private).D;
            string priKey = Hex.ToHexString(privateKey.ToByteArrayUnsigned());
            return new CipherKeyPair(publicKey, priKey);
        }

        public static byte[] GetPublicKey(AsymmetricKeyParameter parameter)
        {
            if (parameter is ECPublicKeyParameters p)
            {
                return p.Q.GetEncoded();
            }

            throw new Exception("not public key parameter");
        }

        public static byte[] GetPrivateKey(AsymmetricKeyParameter parameter)
        {
            if (parameter is ECPrivateKeyParameters p)
            {
                return p.D.ToByteArrayUnsigned();
            }

            throw new Exception("not public key parameter");
        }

        /// <summary>
        /// 从p12文件提取私钥
        /// </summary>
        /// <param name="sm2FileData"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static ECPrivateKeyParameters GetPrivateKeyFromP12(byte[] sm2FileData, string password)
        {
            Asn1Sequence seq = Asn1Sequence.GetInstance(sm2FileData);
            return ParsePrivateKey((Asn1Sequence)seq[1], password);
        }

        /// <summary>
        /// 解析密钥
        /// </summary>
        private static ECPrivateKeyParameters ParsePrivateKey(Asn1Sequence privateInfo, string pwd)
        {
            if (privateInfo.Count != 3)
            {
                throw new Exception("the sm2 file is not right format,can not get the private part");
            }

            if (privateInfo is DerSequence pv)
            {
                if (pv[2] is DerOctetString pvCipher)
                {
                    byte[] pvCipherBytes = pvCipher.GetOctets();
                    byte[] pvBytes = DecryptPrivateKey(pwd, pvCipherBytes);
                    return ParseEcPrivateKey(pvBytes);
                }
            }

            throw new NotSupportedException();
        }

        /// <summary>
        /// 获取公钥
        /// </summary>
        /// <param name="sm2FileData"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static X509Certificate GetCertFromP12(byte[] sm2FileData)
        {
            if (sm2FileData == null)
            {
                throw new Exception("getCertFromSM2 Failure: SM2File sm2FileData should not be null");
            }

            Asn1Sequence seq = Asn1Sequence.GetInstance(sm2FileData);
            X509Certificate[] certs = ParseP12Certs((Asn1Sequence)seq[2]);
            return certs[0];
        }

        /// <summary>
        /// 从p12文件提取证书
        /// </summary>
        /// <param name="publicInfo"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        private static X509Certificate[] ParseP12Certs(Asn1Sequence publicInfo)
        {
            if (publicInfo.Count != 2)
            {
                throw new Exception("the sm2 file is not right format.can not get the public part");
            }

            Asn1OctetString pubOctString = (Asn1OctetString)publicInfo[1];
            X509CertificateStructure structure = X509CertificateStructure.GetInstance(pubOctString.GetOctets());
            return new[] { new X509Certificate(structure) };
        }


        /// <summary>
        /// 获取私钥
        /// </summary>
        /// <param name="pv"></param>
        /// <returns></returns>
        private static ECPrivateKeyParameters ParseEcPrivateKey(byte[] pv)
        {
            BigInteger id = new BigInteger(1, pv);
            return new ECPrivateKeyParameters(id, SmParameters.DomainParameters);
        }

        /// <summary>
        /// 密钥解密
        /// </summary>
        private static byte[] DecryptPrivateKey(string secret, byte[] cipherBytes)
        {
            ParseSecret(secret, out byte[] sm4Key, out byte[] iv);
            return SmUtils.Decrypt(sm4Key, cipherBytes, CipherMode.CBC, CipherPadding.PKCS7, iv);
        }

        /// <summary>
        /// 解析加密键
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        private static void ParseSecret(string secret, out byte[] key, out byte[] iv)
        {
            byte[] secretBytes = DigestUtils.Sm3(Encoding.UTF8.GetBytes(secret), true);
            iv = new byte[16];
            Array.Copy(secretBytes, 0, iv, 0, 16);
            key = new byte[16];
            Array.Copy(secretBytes, 16, key, 0, 16);
        }

        /// <summary>
        /// 密钥加密
        /// </summary>
        private static byte[] EncryptPrivateKey(AsymmetricKeyParameter privateKeyP, string password)
        {
            ParseSecret(password, out byte[] sm4Key, out byte[] iv);
            byte[] sourceBytes = GetPrivateKey(privateKeyP);
            return SmUtils.Encrypt(sm4Key, sourceBytes, CipherMode.CBC, CipherPadding.PKCS7, iv);
        }

        /// <summary>
        /// 创建pkcs12文件
        /// </summary>
        /// <param name="issueName">颁发者</param>
        /// <param name="password">密码</param>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        public static string CreateP12File(string subjectName, string issueName, string password)
        {
            AsymmetricCipherKeyPair keyPair = CreateKeyPairInternal();
            X509Certificate cert = MakeCert(keyPair.Private, keyPair.Public, subjectName, issueName);

            //公钥序列
            DerOctetString pubDerOctetString = new DerOctetString(cert.GetEncoded());
            Asn1EncodableVector publicInfoVector = new Asn1EncodableVector
            {
                SmParameters.sm2Data,
                pubDerOctetString
            };
            DerSequence publicInfo = new DerSequence(publicInfoVector);

            //私钥序列
            byte[] encryptedData = EncryptPrivateKey(keyPair.Private, password);
            DerOctetString prvDerOctetString = new DerOctetString(encryptedData);
            Asn1EncodableVector privateInfoVector = new Asn1EncodableVector
            {
                SmParameters.sm2Data,
                GMObjectIdentifiers.sms4_cbc,
                prvDerOctetString
            };
            DerSequence privateInfo = new DerSequence(privateInfoVector);

            //P12文件序列
            Asn1EncodableVector v = new Asn1EncodableVector
            {
                SmParameters.p12Version,
                privateInfo,
                publicInfo
            };
            byte[] encoding = new BerSequence(v).GetEncoded();
            return Base64.ToBase64String(encoding);
        }

        /// <summary>
        /// 创建证书
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        /// <param name="subjectName"></param>
        /// <param name="issuerName"></param>
        /// <returns></returns>
        public static X509Certificate MakeCert(byte[] privateKey, byte[] publicKey, string subjectName, string issuerName)
        {
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), SmParameters.DomainParameters);
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(SmParameters.DomainParameters.Curve.DecodePoint(publicKey), SmParameters.DomainParameters);
            return MakeCert(privateKeyParameters, publicKeyParameters, subjectName, issuerName);
        }

        /// <summary>
        /// 创建证书
        /// </summary>
        /// <param name="privateParameter"></param>
        /// <param name="publicParameter"></param>
        /// <param name="subjectName"></param>
        /// <param name="issuerName"></param>
        /// <returns></returns>
        public static X509Certificate MakeCert(AsymmetricKeyParameter privateParameter, AsymmetricKeyParameter publicParameter, string subjectName, string issuerName)
        {
            ISignatureFactory sigFact = new Asn1SignatureFactory(GMObjectIdentifiers.sm2sign_with_sm3.Id, privateParameter);
            X509V3CertificateGenerator sm2CertGen = new X509V3CertificateGenerator();
            sm2CertGen.SetSerialNumber(new BigInteger(128, new Random())); //128位   
            sm2CertGen.SetIssuerDN(new X509Name("CN=" + issuerName)); //签发者
            sm2CertGen.SetNotBefore(DateTime.UtcNow.AddDays(-1)); //有效期起
            sm2CertGen.SetNotAfter(DateTime.UtcNow.AddYears(1)); //有效期止
            sm2CertGen.SetSubjectDN(new X509Name("CN=" + subjectName)); //使用者
            sm2CertGen.SetPublicKey(publicParameter); //公钥

            sm2CertGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            sm2CertGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicParameter));
            sm2CertGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(publicParameter));
            sm2CertGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(6));

            X509Certificate sm2Cert = sm2CertGen.Generate(sigFact);
            sm2Cert.CheckValidity();
            sm2Cert.Verify(publicParameter);
            return sm2Cert;
        }
    }
}