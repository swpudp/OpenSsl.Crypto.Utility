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
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文hex</returns>
        internal static byte[] Encrypt(string publicKey, string plainText, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            return EncryptToBytes(publicKeyBytes, plainBytes, cipherMode, padding);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plainBytes">明文</param>
        /// <param name="publicKeyBytes">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        private static byte[] EncryptToBytes(byte[] publicKeyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding padding)
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
        private static string DecryptFromBytes(byte[] privateKeyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding padding)
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
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        internal static string Decrypt(string privateKey, byte[] cipherBytes, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] privateBytes = Convert.FromBase64String(privateKey);
            return DecryptFromBytes(privateBytes, cipherBytes, cipherMode, padding);
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
        private static byte[] SignToBytes(byte[] privateKey, byte[] plainBytes, RsaSignerAlgorithm algorithm)
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
        internal static byte[] Sign(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            var privateKeyBytes = Convert.FromBase64String(privateKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] signBytes = SignToBytes(privateKeyBytes, plainBytes, algorithm);
            return signBytes;
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
        private static bool VerifyFromBytes(byte[] publicKey, byte[] plainBytes, byte[] signedBytes, RsaSignerAlgorithm algorithm)
        {
            var privateKeyInfo = PublicKeyFactory.CreateKey(publicKey);
            string signAlgorithm = GetAlgorithm(algorithm);
            ISigner signer = SignerUtilities.GetSigner(signAlgorithm);
            signer.Init(false, privateKeyInfo);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            return signer.VerifySignature(signedBytes);
        }

        /// <summary>
        /// 验签（Hex）
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名内容</param>
        /// <param name="signBytes">已签名字节数组</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        internal static bool Verify(string publicKey, string plainText, byte[] signBytes, RsaSignerAlgorithm algorithm)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            return VerifyFromBytes(publicKeyBytes, plainBytes, signBytes, algorithm);
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