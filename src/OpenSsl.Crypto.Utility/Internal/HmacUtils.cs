using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// HMAC辅助工具
    /// </summary>
    internal static class HmacUtils
    {
        /// <summary>
        /// HMacSha1摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha1(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha1Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha1摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha1(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha1Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha224摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha224(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha224Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha224摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="key">密钥</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha224(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha224Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha256摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha256(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha256Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha256摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha256(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha256Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha384摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha384(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha384Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha384摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha384(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha384Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }


        /// <summary>
        /// HMacSha512摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha512(string key, string data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha512Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HMacSha512摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha512(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new Sha512Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HmacMd5摘要计算
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="data">待摘要计算字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Md5(string key, string data, Encoding encoding)
        {      
            HMac hmac = new HMac(new MD5Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// HmacMd5摘要计算
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="data">待摘要计算字符</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Md5(string key, byte[] data, Encoding encoding)
        {
            HMac hmac = new HMac(new MD5Digest());
            var hashBytes = hmac.ComputeHashBytes(key, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
