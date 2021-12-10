using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// HMAC加密辅助工具
    /// </summary>
    internal static class HmacUtils
    {
        /// <summary>
        /// HMacSha1加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha1(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha1Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha224加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha224(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha224Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha256加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha256(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha256Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha384加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha384(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha384Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha512加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha512(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha512Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HmacMd5加密
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="data">待加密字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Md5(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new MD5Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
