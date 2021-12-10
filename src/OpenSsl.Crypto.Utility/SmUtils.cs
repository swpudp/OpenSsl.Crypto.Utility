using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 国密辅助类
    /// </summary>
    public static class SmUtils
    {
        /// <summary>
        /// SM3计算摘要
        /// </summary>
        /// <param name="data">待计算字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要字符</returns>
        internal static string Digest(string data, Encoding encoding)
        {
            SM3Digest digest = new SM3Digest();
            byte[] cipherBytes = digest.ComputeHashBytes(data, encoding);
            return Encoding.UTF8.GetString(Hex.Encode(cipherBytes));
        }

        #region 加密

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainText">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>十六进制字符串密文</returns>
        internal static string EncryptToHex(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            //将加密报文转化为字节数组utf8
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] output = EncryptToBytes(secretHex, plainBytes, cipherMode, cipherPadding, iv);
            return Hex.ToHexString(output);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainText">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>Base64密文</returns>
        internal static string EncryptToBase64(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            //将加密报文转化为字节数组utf8
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] output = EncryptToBytes(secretHex, plainBytes, cipherMode, cipherPadding, iv);
            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainBytes">明文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] EncryptToBytes(string secretHex, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            byte[] secretKeyBytes = Hex.Decode(secretHex);
            IBufferedCipher cipher = GetSm4Cipher(secretKeyBytes, cipherMode, cipherPadding, true, iv);
            return cipher.DoFinal(plainBytes);
        }

        #endregion

        #region 解密

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="cipher">从十六进制字符串密文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromBase64(string secretHex, string cipher, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipher);
            return DecryptFromBytes(secretHex, cipherBytes, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secret">十六进制密钥（128位）</param>
        /// <param name="cipher">十六进制字符串密文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromHex(string secret, string cipher, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            byte[] cipherBytes = Hex.Decode(cipher);
            return DecryptFromBytes(secret, cipherBytes, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="cipherBytes">密文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文字节数组</returns>
        internal static string DecryptFromBytes(string secretHex, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            byte[] secretBytes = Hex.Decode(secretHex);
            IBufferedCipher cipher = GetSm4Cipher(secretBytes, cipherMode, cipherPadding, false, iv);
            byte[] output = cipher.DoFinal(cipherBytes);
            return Encoding.UTF8.GetString(output);
        }

        #endregion

        /// <summary>
        /// 获取SM4加密程序
        /// </summary>
        /// <returns></returns>
        private static IBufferedCipher GetSm4Cipher(byte[] secretKeyBytes, CipherMode cipherMode, CipherPadding cipherPadding, bool forEncryption, byte[] iv)
        {
            string algorithmName = AlgorithmUtils.GetCipherAlgorithm("SM4", cipherMode, cipherPadding);
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", secretKeyBytes);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithmName);
            if (algorithmName.Contains("ECB"))
            {
                cipher.Init(forEncryption, key);
                return cipher;
            }
            if (iv == null)
            {
                throw new ArgumentNullException(nameof(iv));
            }
            ParametersWithIV parameters = new ParametersWithIV(key, iv);
            cipher.Init(forEncryption, parameters);
            return cipher;
        }

        /// <summary>
        /// SM2签名（转十六进制字符）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        internal static string SignToHex(string privateKey, string content)
        {
            byte[] result = SignToBytes(privateKey, content);
            return Hex.ToHexString(result);
        }

        /// <summary>
        /// SM2签名（转base64字符）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        internal static string SignToBase64(string privateKey, string content)
        {
            byte[] result = SignToBytes(privateKey, content);
            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// SM2签名（返回字节数组）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <remarks>适用于对签名字节数组自行编码</remarks>
        /// <returns>签名字节数组</returns>
        internal static byte[] SignToBytes(string privateKey, string content)
        {
            //待签名内容
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            byte[] privateKeyBytes = Hex.Decode(privateKey);
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), DomainParameters);
            //创建签名实例
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.Init(true, privateKeyParameters);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            return sm2Signer.GenerateSignature();
        }

        /// <summary>
        /// EC参数
        /// </summary>
        private static readonly X9ECParameters Sm2EcParameters = GMNamedCurves.GetByName("sm2p256v1");

        /// <summary>
        /// EC Domain参数
        /// </summary>
        private static readonly ECDomainParameters DomainParameters = new ECDomainParameters(Sm2EcParameters.Curve, Sm2EcParameters.G, Sm2EcParameters.N);

        /// <summary>
        /// 验证SM2签名（签名值为base64字符）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBase64">签名值（base64）</param>
        /// <returns>是否成功</returns>
        internal static bool VerifyFromBase64(string content, string publicKey, string signBase64)
        {
            byte[] signBytes = Convert.FromBase64String(signBase64);
            return VerifyFromBytes(content, publicKey, signBytes);
        }

        /// <summary>
        /// 验证SM2签名（签名值为十六进制）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signHex">签名值</param>
        /// <returns>是否成功</returns>
        internal static bool VerifyFromHex(string content, string publicKey, string signHex)
        {
            byte[] signResultBytes = Hex.Decode(signHex);
            return VerifyFromBytes(content, publicKey, signResultBytes);
        }

        /// <summary>
        /// 验证sm2签名（字节数组）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <remarks>适用于自定义签名解码</remarks>
        /// <returns>是否成功</returns>
        internal static bool VerifyFromBytes(string content, string publicKey, byte[] signBytes)
        {
            byte[] publicKeyBytes = Hex.Decode(publicKey);
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(DomainParameters.Curve.DecodePoint(publicKeyBytes), DomainParameters);
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            //创建签名实例
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.Init(false, publicKeyParameters);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            return sm2Signer.VerifySignature(signBytes);
        }

        /// <summary>
        /// 生成密钥对（均为十六进制字符串）
        /// </summary>
        /// <param name="compressedPubKey">是否压缩公钥 默认压缩</param>
        /// <returns>密钥对十六进制字符串</returns>
        public static CipherKeyPair GenerateKeyPair(bool compressedPubKey = true)
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");
            X9ECParameters x9EcParameters = GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
            ECDomainParameters eCDomainParameters = new ECDomainParameters(x9EcParameters);
            KeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(eCDomainParameters, random);
            IAsymmetricCipherKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair cipherKeyPair = generator.GenerateKeyPair();
            //提取公钥点
            ECPoint ecPoint = ((ECPublicKeyParameters)cipherKeyPair.Public).Q;
            //公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
            string publicKey = Hex.ToHexString(ecPoint.GetEncoded(compressedPubKey));
            BigInteger privateKey = ((ECPrivateKeyParameters)cipherKeyPair.Private).D;
            string priKey = Hex.ToHexString(privateKey.ToByteArray());
            return new CipherKeyPair(publicKey, priKey);
        }
    }
}