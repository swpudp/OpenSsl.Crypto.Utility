using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// RAS辅助工具
    /// </summary>
    public static class RsaUtils
    {
        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <returns></returns>
        private static AsymmetricCipherKeyPair GenerateKeyPair(int strength)
        {
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            KeyGenerationParameters rsaKeyGenerationParameters =
                new KeyGenerationParameters(new SecureRandom(), strength);
            //初始化参数  
            rsaKeyPairGenerator.Init(rsaKeyGenerationParameters);
            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static CipherKeyPair CreateCipherKeyPair(int length = 1024)
        {
            AsymmetricCipherKeyPair cipherKeyPair = GenerateKeyPair(length);
            return new CipherKeyPair { Private = GetPrivateKey(cipherKeyPair.Private), Public = GetPublicKey(cipherKeyPair.Public) };
        }

        /// <summary>
        /// 从pfx证书获取私钥
        /// </summary>
        /// <param name="certPath"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string GetPrivateKeyFromPfx(string certPath, string password)
        {
            byte[] certBytes = File.ReadAllBytes(certPath);
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.Load(new MemoryStream(certBytes, false), password.ToCharArray());
            IEnumerable<string> aliases = store.Aliases.OfType<string>();
            foreach (var alias in aliases)
            {
                if (store.IsKeyEntry(alias))
                {
                    AsymmetricKeyEntry keyEntry = store.GetKey(alias);
                    return GetPrivateKey(keyEntry.Key);
                }
            }
            throw new Exception("读取证书出错");
        }

        /// <summary>
        /// 从pfx证书获取公钥
        /// </summary>
        /// <param name="certPath"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static string GetPublicKeyFromPfx(string certPath, string password)
        {
            Pkcs12Store keystore = new Pkcs12StoreBuilder().Build();
            using (var stream = File.OpenRead(certPath))
            {
                keystore.Load(stream, password.ToCharArray());
            }
            IEnumerable<string> aliases = keystore.Aliases.OfType<string>();
            foreach (var item in aliases)
            {
                if (keystore.IsKeyEntry(item))
                {
                    X509Certificate x509Certificate = keystore.GetCertificate(item).Certificate;
                    return GetPublicKey(x509Certificate.GetPublicKey());
                }
            }
            throw new Exception("读取证书出错");
        }

        /// <summary>
        /// 获取公钥
        /// </summary>
        /// <param name="keyParameter"></param>
        /// <returns></returns>
        private static string GetPublicKey(AsymmetricKeyParameter keyParameter)
        {
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParameter);
            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
            return Convert.ToBase64String(publicInfoByte);
        }

        /// <summary>
        /// 获取公钥
        /// </summary>
        /// <param name="keyParameter"></param>
        /// <returns></returns>
        private static string GetPrivateKey(AsymmetricKeyParameter keyParameter)
        {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyParameter);
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();
            return Convert.ToBase64String(privateInfoByte);
        }

        /// <summary>
        /// 获取写入pem文件的私钥
        /// </summary>
        /// <param name="keyParameter"></param>
        /// <returns></returns>
        private static string GetPemPrivateKey(AsymmetricKeyParameter keyParameter)
        {
            using (TextWriter textWriter = new StringWriter())
            {
                Org.BouncyCastle.OpenSsl.PemWriter pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter);
                pemWriter.WriteObject(keyParameter);
                pemWriter.Writer.Flush();
                return textWriter.ToString();
            }
        }

        /// <summary>
        /// 获取写入pem文件的公钥
        /// </summary>
        /// <param name="keyParameter"></param>
        /// <returns></returns>
        private static string GetPemPublicKey(AsymmetricKeyParameter keyParameter)
        {
            using (TextWriter textWriter = new StringWriter())
            {
                Org.BouncyCastle.OpenSsl.PemWriter pemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(textWriter);
                pemWriter.WriteObject(keyParameter);
                pemWriter.Writer.Flush();
                return textWriter.ToString();
            }
        }

        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static CipherKeyPair CreatePemCipherKeyPair(int length = 1024)
        {
            AsymmetricCipherKeyPair cipherKeyPair = GenerateKeyPair(length);
            return new CipherKeyPair
            { Private = GetPemPrivateKey(cipherKeyPair.Private), Public = GetPemPublicKey(cipherKeyPair.Public) };
        }

        /// <summary>
        /// 从文件读取私钥
        /// </summary>
        /// <param name="pemPath">文件路径</param>
        /// <returns>私钥对象</returns>
        public static string ReadPrivateKey(string pemPath)
        {
            using (TextReader reader = new StreamReader(pemPath))
            {
                AsymmetricCipherKeyPair privateKeyParameter = (AsymmetricCipherKeyPair)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParameter.Private);
                Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
                byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();
                return Convert.ToBase64String(privateInfoByte);
            }
        }

        /// <summary>
        /// 从文件内容读取私钥
        /// </summary>
        /// <param name="pemContent">文件内容</param>
        /// <param name="onlyPrivateKey">是否仅包含私钥部分</param>
        /// <returns>私钥内容base64</returns>
        public static string GetPrivateKeyFromPemContent(string pemContent, bool onlyPrivateKey)
        {
            string type = onlyPrivateKey ? "PRIVATE KEY" : "RSA PRIVATE KEY";
            AsymmetricKeyParameter priKey = LoadPrivateKeyResource(type, pemContent);
            return GetPrivateKey(priKey);
        }

        /// <summary>
        /// 从私钥文件内容读取公钥
        /// </summary>
        /// <param name="pemContent">私钥文件内容</param>
        /// <remarks>若私钥内容仅包含私钥部分则不支持</remarks>
        /// <returns>公钥内容base64</returns>
        public static string GetPublicKeyFromPrivatePemContent(string pemContent)
        {
            AsymmetricKeyParameter priKey = LoadPublicKeyResource(pemContent);
            return GetPublicKey(priKey);
        }

        /// <summary>
        /// 从文件内容读取公钥
        /// </summary>
        /// <param name="pemContent">文件内容</param>
        /// <returns>私钥对象</returns>
        public static string GetPublicKeyFromPemContent(string pemContent)
        {
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(Convert.FromBase64String(pemContent));
            return Convert.ToBase64String(pubKeyObj.GetEncoded());
        }

        /// <summary>
        /// 从文件内容读取私钥
        /// </summary>
        /// <param name="base64">文件内容</param>
        /// <param name="type">类型</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        private static AsymmetricKeyParameter LoadPrivateKeyResource(string type, string base64)
        {
            PemObject pem = new PemObject(type, Base64.Decode(base64));
            if (pem.Type.EndsWith("RSA PRIVATE KEY"))
            {
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
                return new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent,
                    rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                    rsa.Exponent2, rsa.Coefficient);
            }
            if (pem.Type.EndsWith("PRIVATE KEY"))
            {
                return PrivateKeyFactory.CreateKey(pem.Content);
            }
            throw new ArgumentException("doesn't specify a valid private key", "resource");
        }

        /// <summary>
        /// 从私钥提取公钥
        /// </summary>
        /// <param name="resource"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        private static AsymmetricKeyParameter LoadPublicKeyResource(string resource)
        {
            PemObject pem = new PemObject("RSA PRIVATE KEY", Base64.Decode(resource));
            RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(pem.Content);
            return new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent);
        }

        /// <summary>
        /// 从文件读取公钥
        /// </summary>
        /// <param name="pemPath">文件路径</param>
        /// <returns>公钥base64</returns>
        public static string ReadPublicKey(string pemPath)
        {
            using (TextReader reader = new StreamReader(pemPath))
            {
                RsaKeyParameters publicKeyParameter = (RsaKeyParameters)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
                SubjectPublicKeyInfo subjectPublicKeyInfo =
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKeyParameter);
                Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
                byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
                return Convert.ToBase64String(publicInfoByte);
            }
        }

        #region 加密

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文hex</returns>
        internal static string EncryptToHex(string plainText, string publicKey, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] result = EncryptToBytes(plainBytes, publicKeyBytes, cipherMode, padding);
            return Hex.ToHexString(result);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文base64</returns>
        internal static string EncryptToBase64(string plainText, string publicKey, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] result = EncryptToBytes(plainBytes, publicKeyBytes, cipherMode, padding);
            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainBytes">明文</param>
        /// <param name="publicKeyBytes">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        internal static byte[] EncryptToBytes(byte[] plainBytes, byte[] publicKeyBytes, CipherMode cipherMode, CipherPadding padding)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("RSA", cipherMode, padding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicKeyBytes);
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(pubKeyObj));
            cipher.Init(true, pubKey);
            return cipher.DoFinal(plainBytes, 0, plainBytes.Length);
        }

        #endregion

        #region 解密

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBytes">密文base64</param>
        /// <param name="privateKeyBytes">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        internal static string DecryptFromBytes(byte[] cipherBytes, byte[] privateKeyBytes, CipherMode cipherMode, CipherPadding padding)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("RSA", cipherMode, padding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.CreateKey(privateKeyBytes);
            cipher.Init(false, privateKeyParameter);
            byte[] result = cipher.DoFinal(cipherBytes, 0, cipherBytes.Length);
            return Encoding.UTF8.GetString(result);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherHex">密文hex</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        internal static string DecryptFromHex(string cipherHex, string privateKey, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] cipherBytes = Hex.Decode(cipherHex);
            byte[] privateBytes = Convert.FromBase64String(privateKey);
            return DecryptFromBytes(cipherBytes, privateBytes, cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBase64">密文base64</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        internal static string DecryptFromBase64(string cipherBase64, string privateKey, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherBase64);
            byte[] privateBytes = Convert.FromBase64String(privateKey);
            return DecryptFromBytes(cipherBytes, privateBytes, cipherMode, padding);
        }

        #endregion

        /// <summary>
        /// 生成自签名证书
        /// </summary>
        /// <param name="domains">域集合</param>
        /// <param name="keySizeBits">证书大小</param>
        /// <param name="validFrom">有效期开始日期</param>
        /// <param name="validTo">有效期结束日期</param>
        /// <param name="caPrivateCert">ca私钥字符</param>
        /// <returns>证书文件字符串</returns>
        public static string GenerateBySelf(IList<string> domains, int keySizeBits, DateTime validFrom, DateTime validTo, out string caPrivateCert)
        {
            var keys = GenerateKeyPair(keySizeBits);
            var cert = GenerateCertificate(domains, keys.Public, validFrom, validTo, domains.First(), null,
                keys.Private, 1);
            using (var priWriter = new StringWriter())
            {
                var priPemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(priWriter);
                priPemWriter.WriteObject(keys.Private);
                priPemWriter.Writer.Flush();
                caPrivateCert = priWriter.ToString();
            }

            using (var pubWriter = new StringWriter())
            {
                var pubPemWriter = new Org.BouncyCastle.OpenSsl.PemWriter(pubWriter);
                pubPemWriter.WriteObject(cert);
                pubPemWriter.Writer.Flush();
                return pubWriter.ToString();
            }
        }

        /// <summary>
        /// 生成CA签名证书
        /// </summary>
        /// <param name="domains"></param>
        /// <param name="keySizeBits"></param>
        /// <param name="validFrom"></param>
        /// <param name="validTo"></param>
        /// <param name="caPublicCerPath"></param>
        /// <param name="caPrivateKeyPath"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] GenerateFromCa(IList<string> domains, int keySizeBits, DateTime validFrom, DateTime validTo, string caPublicCerPath, string caPrivateKeyPath, string password = default)
        {
            if (!File.Exists(caPublicCerPath))
            {
                throw new FileNotFoundException(caPublicCerPath);
            }

            if (!File.Exists(caPrivateKeyPath))
            {
                throw new FileNotFoundException(caPublicCerPath);
            }

            X509Certificate caCert;
            using (StreamReader pubReader = new StreamReader(caPublicCerPath, Encoding.UTF8))
            {
                caCert = (X509Certificate)new Org.BouncyCastle.OpenSsl.PemReader(pubReader).ReadObject();
            }

            AsymmetricKeyParameter caPrivateKey;
            using (StreamReader priReader = new StreamReader(caPrivateKeyPath, Encoding.UTF8))
            {
                Org.BouncyCastle.OpenSsl.PemReader reader = new Org.BouncyCastle.OpenSsl.PemReader(priReader);
                caPrivateKey = ((AsymmetricCipherKeyPair)reader.ReadObject()).Private;
            }

            string caSubjectName = GetSubjectName(caCert);
            AsymmetricCipherKeyPair keys = GenerateKeyPair(keySizeBits);
            X509Certificate cert = GenerateCertificate(domains, keys.Public, validFrom, validTo, caSubjectName,
                caCert.GetPublicKey(), caPrivateKey, null);
            return GeneratePfx(cert, keys.Private, password);
        }

        /// <summary>
        /// 生成证书
        /// </summary>
        /// <param name="domains"></param>
        /// <param name="subjectPublic"></param>
        /// <param name="validFrom"></param>
        /// <param name="validTo"></param>
        /// <param name="issuerName"></param>
        /// <param name="issuerPublic"></param>
        /// <param name="issuerPrivate"></param>
        /// <param name="caPathLengthConstraint"></param>
        /// <returns></returns>
        private static X509Certificate GenerateCertificate(IList<string> domains, AsymmetricKeyParameter subjectPublic,
            DateTime validFrom, DateTime validTo, string issuerName, AsymmetricKeyParameter issuerPublic,
            AsymmetricKeyParameter issuerPrivate, int? caPathLengthConstraint)
        {
            Asn1SignatureFactory signatureFactory = issuerPrivate is ECPrivateKeyParameters
                ? new Asn1SignatureFactory(X9ObjectIdentifiers.ECDsaWithSha256.ToString(), issuerPrivate)
                : new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerPrivate);

            X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(new X509Name("CN=" + issuerName));
            certGenerator.SetSubjectDN(new X509Name("CN=" + domains.First()));
            certGenerator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
            certGenerator.SetNotBefore(validFrom);
            certGenerator.SetNotAfter(validTo);
            certGenerator.SetPublicKey(subjectPublic);

            if (issuerPublic != null)
            {
                AuthorityKeyIdentifierStructure akis = new AuthorityKeyIdentifierStructure(issuerPublic);
                certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, akis);
            }

            if (caPathLengthConstraint >= 0)
            {
                BasicConstraints basicConstraints = new BasicConstraints(caPathLengthConstraint.Value);
                certGenerator.AddExtension(X509Extensions.BasicConstraints, true, basicConstraints);
                certGenerator.AddExtension(X509Extensions.KeyUsage, false,
                    new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.CrlSign | KeyUsage.KeyCertSign));
            }
            else
            {
                BasicConstraints basicConstraints = new BasicConstraints(cA: false);
                certGenerator.AddExtension(X509Extensions.BasicConstraints, true, basicConstraints);
                certGenerator.AddExtension(X509Extensions.KeyUsage, false,
                    new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            }

            certGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            GeneralName[] names = domains.Select(domain =>
            {
                int nameType = GeneralName.DnsName;
                if (IPAddress.TryParse(domain, out _))
                {
                    nameType = GeneralName.IPAddress;
                }

                return new GeneralName(nameType, domain);
            }).ToArray();

            GeneralNames subjectAltName = new GeneralNames(names);
            certGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);
            return certGenerator.Generate(signatureFactory);
        }

        /// <summary>
        /// 生成pfx
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private static byte[] GeneratePfx(X509Certificate cert, AsymmetricKeyParameter privateKey, string password)
        {
            string subject = GetSubjectName(cert);
            Pkcs12Store pkcs12Store = new Pkcs12Store();
            X509CertificateEntry certEntry = new X509CertificateEntry(cert);
            pkcs12Store.SetCertificateEntry(subject, certEntry);
            pkcs12Store.SetKeyEntry(subject, new AsymmetricKeyEntry(privateKey), new[] { certEntry });
            using (MemoryStream pfxStream = new MemoryStream())
            {
                pkcs12Store.Save(pfxStream, password?.ToCharArray(), new SecureRandom());
                return pfxStream.ToArray();
            }
        }

        /// <summary>
        /// 获取Subject
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        private static string GetSubjectName(X509Certificate cert)
        {
            string subject = cert.SubjectDN.ToString();
            if (subject.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                subject = subject.Substring(3);
            }
            return subject;
        }

        #region 签名

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="privateKey">私钥字节</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        internal static byte[] SignToBytes(byte[] privateKey, byte[] plainBytes, RsaSignerAlgorithm algorithm)
        {
            var privateKeyInfo = PrivateKeyFactory.CreateKey(privateKey);
            string signAlgorithm = GetAlgorithm(algorithm);
            ISigner signer = SignerUtilities.GetSigner(signAlgorithm);
            signer.Init(true, privateKeyInfo);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// 签名(十六进制)
        /// </summary>
        /// <param name="privateKey">私钥base64</param>
        /// <param name="plainText">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        internal static string SignToHex(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            var privateKeyBytes = Convert.FromBase64String(privateKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signBytes = SignToBytes(privateKeyBytes, plainBytes, algorithm);
            return Hex.ToHexString(signBytes);
        }

        /// <summary>
        /// 签名(Base64)
        /// </summary>
        /// <param name="privateKey">私钥base64</param>
        /// <param name="plainText">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        internal static string SignToBase64(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            var privateKeyBytes = Convert.FromBase64String(privateKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signBytes = SignToBytes(privateKeyBytes, plainBytes, algorithm);
            return Convert.ToBase64String(signBytes);
        }

        #endregion

        #region 验签

        /// <summary>
        /// 验签
        /// </summary>
        /// <param name="publicKey">公钥字节</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="signedBytes">已签名字节</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        internal static bool VerifyFromBytes(byte[] publicKey, byte[] plainBytes, byte[] signedBytes, RsaSignerAlgorithm algorithm)
        {
            var privateKeyInfo = PublicKeyFactory.CreateKey(publicKey);
            string signAlgorithm = GetAlgorithm(algorithm);
            ISigner signer = SignerUtilities.GetSigner(signAlgorithm);
            signer.Init(false, privateKeyInfo);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            return signer.VerifySignature(signedBytes);
        }

        /// <summary>
        /// 验签(十六进制)
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名字符</param>
        /// <param name="signedHex">已签名字符</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        internal static bool VerifyFromHex(string publicKey, string plainText, string signedHex, RsaSignerAlgorithm algorithm)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signedBytes = Hex.Decode(signedHex);
            return VerifyFromBytes(publicKeyBytes, plainBytes, signedBytes, algorithm);
        }

        /// <summary>
        /// 验签(Base64)
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名字符</param>
        /// <param name="signedHex">已签名字符</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        internal static bool VerifyFromBase64(string publicKey, string plainText, string signedHex, RsaSignerAlgorithm algorithm)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signedBytes = Convert.FromBase64String(signedHex);
            return VerifyFromBytes(publicKeyBytes, plainBytes, signedBytes, algorithm);
        }

        #endregion

        /// <summary>
        /// 获取签名
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        private static string GetAlgorithm(RsaSignerAlgorithm algorithm)
        {
            if (RsaSignerAlgorithms.TryGetValue(algorithm, out string signAlgorithm))
            {
                return signAlgorithm;
            }

            throw new NotSupportedException("签名算法有误");
        }

        /// <summary>
        /// rsa签名算法
        /// </summary>
        private static readonly IDictionary<RsaSignerAlgorithm, string> RsaSignerAlgorithms =
            new Dictionary<RsaSignerAlgorithm, string>
            {
                [RsaSignerAlgorithm.MD2withRSA] = "MD2withRSA",
                [RsaSignerAlgorithm.MD5withRSA] = "MD5withRSA",
                [RsaSignerAlgorithm.SHA1withRSA] = "SHA1withRSA",
                [RsaSignerAlgorithm.SHA224withRSA] = "SHA224withRSA",
                [RsaSignerAlgorithm.SHA256withRSA] = "SHA256withRSA",
                [RsaSignerAlgorithm.SHA384withRSA] = "SHA384withRSA",
                [RsaSignerAlgorithm.SHA512withRSA] = "SHA512withRSA",
                [RsaSignerAlgorithm.RIPEMD128withRSA] = "RIPEMD128withRSA",
                [RsaSignerAlgorithm.RIPEMD160withRSA] = "RIPEMD160withRSA"
            };
    }
}