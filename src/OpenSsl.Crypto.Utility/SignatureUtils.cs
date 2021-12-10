namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 数据签名工具
    /// </summary>
    public static class SignatureUtils
    {
        #region RSA

        #region 签名

        /// <summary>
        /// RSA签名(Base64)
        /// </summary>
        /// <param name="privateKey">私钥base64</param>
        /// <param name="plainText">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        public static string RsaSignToBase64(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.SignToBase64(privateKey, plainText, algorithm);
        }

        /// <summary>
        /// RSA签名(十六进制)
        /// </summary>
        /// <param name="privateKey">私钥base64</param>
        /// <param name="plainText">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        public static string RsaSignToHex(string privateKey, string plainText, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.SignToHex(privateKey, plainText, algorithm);
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="privateKey">私钥字节</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="algorithm">算法名称</param>
        /// <returns></returns>
        public static byte[] RsaSignToBytes(byte[] privateKey, byte[] plainBytes, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.SignToBytes(privateKey, plainBytes, algorithm);
        }

        #endregion

        #region 验签

        /// <summary>
        /// RSA验签(Base64)
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名字符</param>
        /// <param name="signedHex">已签名字符</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        public static bool RsaVerifyFromBase64(string publicKey, string plainText, string signedHex, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.VerifyFromBase64(publicKey, plainText, signedHex, algorithm);
        }

        /// <summary>
        /// RSA验签
        /// </summary>
        /// <param name="publicKey">公钥字节</param>
        /// <param name="plainBytes">待签名字节</param>
        /// <param name="signedBytes">已签名字节</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        public static bool RsaVerifyFromBytes(byte[] publicKey, byte[] plainBytes, byte[] signedBytes, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.VerifyFromBytes(publicKey, plainBytes, signedBytes, algorithm);
        }

        /// <summary>
        /// RSA验签(十六进制)
        /// </summary>
        /// <param name="publicKey">公钥base64</param>
        /// <param name="plainText">待签名字符</param>
        /// <param name="signedHex">已签名字符</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns></returns>
        public static bool RsaVerifyFromHex(string publicKey, string plainText, string signedHex, RsaSignerAlgorithm algorithm)
        {
            return RsaUtils.VerifyFromHex(publicKey, plainText, signedHex, algorithm);
        }

        #endregion

        #endregion

        #region SM2

        #region 签名

        /// <summary>
        /// SM2签名（转十六进制字符）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        public static string Sm2SignToHex(string privateKey, string content)
        {
            return SmUtils.SignToHex(privateKey, content);
        }

        /// <summary>
        /// SM2签名（转base64字符）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <returns>签名字符串</returns>
        public static string Sm2SignToBase64(string privateKey, string content)
        {
            return SmUtils.SignToBase64(privateKey, content);
        }

        /// <summary>
        /// SM2签名（返回字节数组）
        /// </summary>
        /// <param name="privateKey">公钥</param>
        /// <param name="content">待签名内容</param>
        /// <remarks>适用于对签名字节数组自行编码</remarks>
        /// <returns>签名字节数组</returns>
        public static byte[] Sm2SignToBytes(string privateKey, string content)
        {
            return SmUtils.SignToBytes(privateKey, content);
        }

        #endregion

        #region 验签

        /// <summary>
        /// SM2验证签名（签名值为base64字符）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBase64">签名值（base64）</param>
        /// <returns>是否成功</returns>
        public static bool Sm2VerifyFromBase64(string content, string publicKey, string signBase64)
        {
            return SmUtils.VerifyFromBase64(content, publicKey, signBase64);
        }

        /// <summary>
        /// SM2验证签名（签名值为十六进制）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signHex">签名值</param>
        /// <returns>是否成功</returns>
        public static bool Sm2VerifyFromHex(string content, string publicKey, string signHex)
        {
            return SmUtils.VerifyFromHex(content, publicKey, signHex);
        }

        /// <summary>
        /// SM2验证签名（字节数组）
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="content">待签名内容,如有其他处理如加密一次等，请先处理后传入</param>
        /// <param name="signBytes">签名值字节数组</param>
        /// <remarks>适用于自定义签名解码</remarks>
        /// <returns>是否成功</returns>
        public static bool Sm2VerifyFromBytes(string content, string publicKey, byte[] signBytes)
        {
            return SmUtils.VerifyFromBytes(content, publicKey, signBytes);
        }

        #endregion

        #endregion
    }
}
