using System;
using OpenSsl.Crypto.Utility.Internal;
using Org.BouncyCastle.X509;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 数据签名工具（非对称算法）
    /// </summary>
    public static class SignatureUtils
    {
        #region RSA

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="privateKey">私钥base64</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        public static byte[] RsaSign(byte[] privateKey, byte[] plainBytes, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.Sign(privateKey, plainBytes, algorithm);
        }

        /// <summary>
        /// RSA验签
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainBytes">待签名字符</param>
        /// <param name="signBytes">已签名字节数组</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        public static bool RsaVerify(byte[] publicKey, byte[] plainBytes, byte[] signBytes, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.Verify(publicKey, plainBytes, signBytes, algorithm);
        }

        #endregion

        #region SM2

        /// <summary>
        /// SM2签名
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <param name="forPlainDsa">是否原始字节，否则按der编码</param>
        /// <param name="forSm2">使用sm2编码</param>
        /// <returns>签名字符串</returns>
        public static byte[] Sm2Sign(byte[] privateKey, byte[] content, bool forPlainDsa, bool forSm2)
        {
            return SmUtils.Sign(privateKey, content, forPlainDsa, forSm2);
        }

        /// <summary>
        /// p7带原文签名
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="x509Cert">证书</param>
        /// <param name="sourceData">待签名字节</param>
        /// <returns>签名字符串</returns>
        public static byte[] Sm2Sign(byte[] privateKey, X509Certificate x509Cert, byte[] sourceData)
        {
            return SmUtils.Sign(privateKey, x509Cert, sourceData);
        }

        /// <summary>
        /// SM2验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <param name="forPlainDsa">是否返回原文，否则按der编码返回</param>
        /// <param name="forSm2">使用sm2编码</param>
        /// <returns>是否成功</returns>
        public static bool Sm2Verify(byte[] publicKey, byte[] content, byte[] signBytes, bool forPlainDsa, bool forSm2)
        {
            return SmUtils.Verify(publicKey, content, signBytes, forPlainDsa, forSm2);
        }

        /// <summary>
        /// pkcs7带原文验签
        /// </summary>
        /// <param name="sourceData">原文字节</param>
        /// <param name="signature">签名字节</param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        public static bool Sm2Verify(byte[] sourceData, byte[] signature)
        {
            return SmUtils.Verify(sourceData, signature);
        }

        #endregion
    }
}