using System.Text;
using OpenSsl.Crypto.Utility.Internal;

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
            return HexUtils.ToHexString(ShaUtils.Sha1(encoding.GetBytes(data)));
        }

        /// <summary>
        /// sha1摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha1(byte[] data)
        {
            return ShaUtils.Sha1(data);
        }

        /// <summary>
        /// sha224摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha224(string data, Encoding encoding)
        {
            return HexUtils.ToHexString(ShaUtils.Sha224(encoding.GetBytes(data)));
        }

        /// <summary>
        /// sha224摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha224(byte[] data)
        {
            return ShaUtils.Sha224(data);
        }

        /// <summary>
        /// sha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha256(string data, Encoding encoding)
        {
            return HexUtils.ToHexString(ShaUtils.Sha256(encoding.GetBytes(data)));
        }

        /// <summary>
        /// sha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha256(byte[] data)
        {
            return ShaUtils.Sha256(data);
        }

        /// <summary>
        /// sha384摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha384(string data, Encoding encoding)
        {
            return HexUtils.ToHexString(ShaUtils.Sha384(encoding.GetBytes(data)));
        }

        /// <summary>
        /// sha384摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha384(byte[] data)
        {
            return ShaUtils.Sha384(data);
        }

        /// <summary>
        /// sha512摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha512(string data, Encoding encoding)
        {
            return HexUtils.ToHexString(ShaUtils.Sha512(encoding.GetBytes(data)));
        }

        /// <summary>
        /// sha512摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha512(byte[] data)
        {
            return ShaUtils.Sha512(data);
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
        /// HMacSha1摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha1(string key, byte[] data, Encoding encoding)
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
        /// HMacSha224摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha224(string key, byte[] data, Encoding encoding)
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
        /// HMacSha256摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha256(string key, byte[] data, Encoding encoding)
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
        /// HMacSha384摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha384(string key, byte[] data, Encoding encoding)
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
        /// HMacSha512摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacSha512(string key, byte[] data, Encoding encoding)
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

        /// <summary>
        /// HmacMd5摘要
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="data">待摘要字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string HmacMd5(string key, byte[] data, Encoding encoding)
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
            return HexUtils.ToHexString(Md5Utils.Digest(encoding.GetBytes(data)));
        }

        /// <summary>
        /// md5计算摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <returns>摘要</returns>
        public static byte[] Md5(byte[] data)
        {
            return Md5Utils.Digest(data);
        }

        #endregion

        #region 国密SM3

        /// <summary>
        /// 国密SM3计算摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="forKdf">是否使用派生函数</param>
        /// <returns>摘要</returns>
        public static byte[] Sm3(byte[] data, bool forKdf = false)
        {
            return SmUtils.Digest(data, forKdf);
        }

        /// <summary>
        /// 国密SM3计算摘要
        /// </summary>
        /// <param name="data">待计算摘要内容</param>
        /// <param name="encoding">编码</param>
        /// <param name="forKdf">是否使用派生函数</param>
        /// <returns>摘要</returns>
        public static string Sm3(string data, Encoding encoding, bool forKdf = false)
        {
            return HexUtils.ToHexString(SmUtils.Digest(encoding.GetBytes(data), forKdf));
        }

        #endregion
    }
}