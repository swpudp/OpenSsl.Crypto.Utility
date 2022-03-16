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
        /// <param name="plainText">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        public static byte[] RsaSign(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.Sign(privateKey, plainText, algorithm);
        }

        /// <summary>
        /// RSA验签
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名字符</param>
        /// <param name="signBytes">已签名字节数组</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        public static bool RsaVerify(string publicKey, string plainText, byte[] signBytes, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.Verify(publicKey, plainText, signBytes, algorithm);
        }

        #endregion

        #region SM2

        /// <summary>
        /// SM2签名
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        public static byte[] Sm2Sign(string privateKey, string content)
        {
            return SmUtils.Sign(privateKey, content);
        }

        /// <summary>
        /// SM2验签
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <returns>是否成功</returns>
        public static bool Sm2Verify(string publicKey, string content, byte[] signBytes)
        {
            return SmUtils.Verify(publicKey, content, signBytes);
        }

        #endregion
    }
}
