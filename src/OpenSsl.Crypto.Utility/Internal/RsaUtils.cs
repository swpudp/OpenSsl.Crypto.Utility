using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// RAS辅助工具
    /// </summary>
    internal static class RsaUtils
    {
        #region 加密

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainBytes">明文</param>
        /// <param name="publicKeyBytes">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(byte[] publicKeyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding padding)
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
        internal static byte[] Decrypt(byte[] privateKeyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding padding)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("RSA", cipherMode, padding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            AsymmetricKeyParameter privateKeyParameter = PrivateKeyFactory.CreateKey(privateKeyBytes);
            cipher.Init(false, privateKeyParameter);
            byte[] result = cipher.DoFinal(cipherBytes, 0, cipherBytes.Length);
            return (result);
        }

        #endregion

        #region 签名

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="privateKey">私钥字节</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        internal static byte[] Sign(byte[] privateKey, byte[] plainBytes, RsaSignerAlgorithm algorithm)
        {
            var privateKeyInfo = PrivateKeyFactory.CreateKey(privateKey);
            string signAlgorithm = GetAlgorithm(algorithm);
            ISigner signer = SignerUtilities.GetSigner(signAlgorithm);
            signer.Init(true, privateKeyInfo);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            return signer.GenerateSignature();
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
        internal static bool Verify(byte[] publicKey, byte[] plainBytes, byte[] signedBytes, RsaSignerAlgorithm algorithm)
        {
            var privateKeyInfo = PublicKeyFactory.CreateKey(publicKey);
            string signAlgorithm = GetAlgorithm(algorithm);
            ISigner signer = SignerUtilities.GetSigner(signAlgorithm);
            signer.Init(false, privateKeyInfo);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            return signer.VerifySignature(signedBytes);
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
        private static readonly IDictionary<RsaSignerAlgorithm, string> RsaSignerAlgorithms = new Dictionary<RsaSignerAlgorithm, string>
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