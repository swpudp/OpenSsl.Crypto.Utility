using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 摘要工具
    /// </summary>
    public static class DigestUtils
    {
        #region sha摘要

        /// <summary>
        /// sha1摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha1(string data, Encoding encoding)
        {
            return ShaUtils.Sha1(data, encoding);
        }

        /// <summary>
        /// sha224摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha224(string data, Encoding encoding)
        {
            return ShaUtils.Sha224(data, encoding);
        }

        /// <summary>
        /// sha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha256(string data, Encoding encoding)
        {
            return ShaUtils.Sha256(data, encoding);
        }

        /// <summary>
        /// sha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static byte[] Sha256Bytes(string data, Encoding encoding)
        {
            return ShaUtils.Sha256Bytes(data, encoding);
        }

        /// <summary>
        /// sha384摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha384(string data, Encoding encoding)
        {
            return ShaUtils.Sha384(data, encoding);
        }

        /// <summary>
        /// sha512摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha512(string data, Encoding encoding)
        {
            return ShaUtils.Sha512(data, encoding);
        }

        #endregion

        #region hmac摘要

        /// <summary>
        /// HMacSha1摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha1(string key, string data, Encoding encoding)
        {
            return HmacUtils.Sha1(key, data, encoding);
        }

        /// <summary>
        /// HMacSha224摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha224(string key, string data, Encoding encoding)
        {
            return HmacUtils.Sha224(key, data, encoding);
        }

        /// <summary>
        /// HMacSha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha256(string key, string data, Encoding encoding)
        {
            return HmacUtils.Sha256(key, data, encoding);
        }

        /// <summary>
        /// HMacSha384摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha384(string key, string data, Encoding encoding)
        {
            return HmacUtils.Sha384(key, data, encoding);
        }

        /// <summary>
        /// HMacSha512摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha512(string key, string data, Encoding encoding)
        {
            return HmacUtils.Sha512(key, data, encoding);
        }

        /// <summary>
        /// HmacMd5摘要
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="data">待摘要字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacMd5(string key, string data, Encoding encoding)
        {
            return HmacUtils.Md5(key, data, encoding);
        }

        #endregion

        #region md5

        /// <summary>
        /// md5计算摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Md5(string data, Encoding encoding)
        {
            return Md5Utils.Digest(data, encoding);
        }

        #endregion

        #region 国密SM3

        /// <summary>
        /// 国密SM3计算摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sm3(string data, Encoding encoding)
        {
            return SmUtils.Digest(data, encoding);
        }

        #endregion
    }
}
