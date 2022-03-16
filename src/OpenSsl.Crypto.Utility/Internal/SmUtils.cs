using System;
using System.Text;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// 国密辅助类
    /// </summary>
    internal static class SmUtils
    {
        /// <summary>
        /// SM3计算摘要
        /// </summary>
        /// <param name="data">待计算字符内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要字符</returns>
        internal static string Digest(string data, Encoding encoding)
        {
            SM3Digest digest = new SM3Digest();
            byte[] cipherBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(cipherBytes));
        }

        /// <summary>
        /// SM3计算摘要
        /// </summary>
        /// <param name="data">待计算字节数组</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要字符</returns>
        internal static string Digest(byte[] data, Encoding encoding)
        {
            SM3Digest digest = new SM3Digest();
            byte[] cipherBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(cipherBytes));
        }

        #region 加密

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">密钥（Hex）</param>
        /// <param name="plainText">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            //将加密报文转化为字节数组utf8
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            return EncryptToBytes(secretHex, plainBytes, cipherMode, cipherPadding, iv);
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
        private static byte[] EncryptToBytes(string secretHex, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
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
        /// <param name="secretHex">密钥（Hex）</param>
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        internal static string Decrypt(string secretHex, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return DecryptFromBytes(secretHex, cipherBytes, cipherMode, cipherPadding, iv);
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
        private static string DecryptFromBytes(string secretHex, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
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
        /// SM2签名
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        internal static byte[] Sign(string privateKey, string content)
        {
            //待签名内容
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            byte[] result = SignToBytes(privateKey, contentBytes);
            return result;
        }

        /// <summary>
        /// SM2签名
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="contentBytes">待签名内容</param>
        /// <remarks>适用于对签名字节数组自行编码</remarks>
        /// <returns>签名字节数组</returns>
        private static byte[] SignToBytes(string privateKey, byte[] contentBytes)
        {
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
        /// 验证SM2签名（Hex）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值（Hex）</param>
        /// <returns>是否成功</returns>
        internal static bool Verify(string publicKey, string content, byte[] signBytes)
        {
            byte[] publicKeyBytes = Hex.Decode(publicKey);
            byte[] contentBytes = Encoding.UTF8.GetBytes(content);
            return Verify(publicKeyBytes, contentBytes, signBytes);
        }

        /// <summary>
        /// 验证sm2签名（字节数组）
        /// </summary>
        /// <param name="publicKeyBytes">公钥</param>
        /// <param name="contentBytes">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <remarks>适用于自定义签名解码</remarks>
        /// <returns>是否成功</returns>
        private static bool Verify(byte[] publicKeyBytes, byte[] contentBytes, byte[] signBytes)
        {
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(DomainParameters.Curve.DecodePoint(publicKeyBytes), DomainParameters);
            //创建签名实例
            SM2Signer sm2Signer = new SM2Signer();
            sm2Signer.Init(false, publicKeyParameters);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            return sm2Signer.VerifySignature(signBytes);
        }
    }
}