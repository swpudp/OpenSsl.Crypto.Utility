using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

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
        /// <param name="forKdf"></param>
        /// <returns>摘要字符</returns>
        internal static byte[] Digest(byte[] data, bool forKdf)
        {
            SM3Digest digest = new SM3Digest();
            byte[] cipherBytes = digest.ComputeHashBytes(data, forKdf);
            return cipherBytes;
        }

        #region 加密

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="keyBytes">密钥</param>
        /// <param name="plainBytes">明文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(byte[] keyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv)
        {
            IBufferedCipher cipher = GetSm4Cipher(keyBytes, cipherMode, cipherPadding, true, iv);
            return cipher.DoFinal(plainBytes);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="keyBytes">密钥</param>
        /// <param name="plainBytes">明文字节</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(byte[] keyBytes, byte[] plainBytes)
        {
            SM2Engine cipher = new SM2Engine();
            ECPoint ecPoint = SmParameters.DomainParameters.Curve.DecodePoint(keyBytes);
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(ecPoint, SmParameters.DomainParameters);
            ParametersWithRandom parametersWithRandom = new ParametersWithRandom(publicKeyParameters, new SecureRandom());
            cipher.Init(true, parametersWithRandom);
            return cipher.ProcessBlock(plainBytes, 0, plainBytes.Length);
        }

        #endregion

        #region 解密

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="keyBytes">密钥</param>
        /// <param name="cipherBytes">密文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文字节数组</returns>
        internal static byte[] Decrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv)
        {
            IBufferedCipher cipher = GetSm4Cipher(keyBytes, cipherMode, cipherPadding, false, iv);
            byte[] output = cipher.DoFinal(cipherBytes);
            return output;
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="keyBytes">密钥</param>
        /// <param name="cipherBytes">密文字节</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文字节数组</returns>
        internal static byte[] Decrypt(byte[] keyBytes, byte[] cipherBytes)
        {
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, keyBytes), SmParameters.DomainParameters);
            SM2Engine cipher = new SM2Engine();
            cipher.Init(false, privateKeyParameters);
            byte[] output = cipher.ProcessBlock(cipherBytes, 0, cipherBytes.Length);
            return output;
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
            if (algorithmName.Contains("ECB") || iv == null)
            {
                cipher.Init(forEncryption, key);
                return cipher;
            }
            ICipherParameters parameters = new ParametersWithIV(key, iv);
            cipher.Init(forEncryption, parameters);
            return cipher;
        }

        /// <summary>
        /// pkcs7带原文签名
        /// </summary>
        /// <returns></returns>
        internal static byte[] Sign(byte[] privateKey, X509Certificate x509Cert, byte[] sourceData)
        {
            byte[] signature = SmUtils.Sign(privateKey, sourceData, true);
            return SmPkcs7Utils.Package(signature, x509Cert, sourceData);
        }

        /// <summary>
        /// SM2签名
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="contentBytes">待签名内容</param>
        /// <param name="forSm2">使用sm2编码</param>
        /// <remarks>适用于对签名字节数组自行编码</remarks>
        /// <returns>签名字节数组</returns>
        internal static byte[] Sign(byte[] privateKey, byte[] contentBytes, bool forSm2)
        {
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), SmParameters.DomainParameters);
            //创建签名实例
            SM2Signer sm2Signer = GetSigner(privateKeyParameters, true, forSm2);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            byte[] signature = sm2Signer.GenerateSignature();
            return signature;
        }

        /// <summary>
        /// 验证sm2签名（字节数组）
        /// </summary>
        /// <param name="cert">证书</param>
        /// <param name="contentBytes">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <param name="forSm2">是否sm2编码</param>
        /// <returns>是否成功</returns>
        internal static bool Verify(X509Certificate cert, byte[] contentBytes, byte[] signBytes, bool forSm2)
        {
            //创建签名实例
            SM2Signer sm2Signer = GetSigner(cert.GetPublicKey(), false, forSm2);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            return sm2Signer.VerifySignature(signBytes);
        }

        /// <summary>
        /// 验证sm2签名（字节数组）
        /// </summary>
        /// <param name="publicKeyBytes">公钥</param>
        /// <param name="contentBytes">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <param name="forSm2">是否sm2编码</param>
        /// <returns>是否成功</returns>
        internal static bool Verify(byte[] publicKeyBytes, byte[] contentBytes, byte[] signBytes, bool forSm2)
        {
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(SmParameters.DomainParameters.Curve.DecodePoint(publicKeyBytes), SmParameters.DomainParameters);
            SM2Signer sm2Signer = GetSigner(publicKeyParameters, false, forSm2);
            sm2Signer.BlockUpdate(contentBytes, 0, contentBytes.Length);
            return sm2Signer.VerifySignature(signBytes);
        }

        /// <summary>
        /// 获取签名实例
        /// </summary>
        /// <param name="publicKeyParameters"></param>
        /// <param name="forSign"></param>
        /// <param name="forSm2"></param>
        /// <returns></returns>
        private static SM2Signer GetSigner(AsymmetricKeyParameter publicKeyParameters, bool forSign, bool forSm2)
        {
            IDsaEncoding dsaEncoding;
            if (forSm2)
            {
                dsaEncoding = PlainDsaEncoding.Instance;
            }
            else
            {
                dsaEncoding = StandardDsaEncoding.Instance;
            }

            //创建签名实例
            SM2Signer sm2Signer = new SM2Signer(dsaEncoding);
            sm2Signer.Init(forSign, publicKeyParameters);
            return sm2Signer;
        }

        /// <summary>
        /// pkcs7带原文验签
        /// </summary>
        /// <param name="sourceData">原文字节</param>
        /// <param name="signature">签名字节</param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public static bool Verify(byte[] sourceData, byte[] signature)
        {
            return SmPkcs7Utils.UnPackage(sourceData, signature, Verify);
        }
    }
}