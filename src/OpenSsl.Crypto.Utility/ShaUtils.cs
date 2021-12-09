using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    public static class ShaUtils
    {
        /// <summary>
        /// sha1加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha1(string data, Encoding encoding)
        {
            Sha1Digest sha1Digest = new Sha1Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(sha1Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha224加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha224(string data, Encoding encoding)
        {
            Sha224Digest sha224Digest = new Sha224Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(sha224Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha256加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha256(string data, Encoding encoding)
        {
            Sha256Digest sha256Digest = new Sha256Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(sha256Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha256加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static byte[] Sha256Bytes(string data, Encoding encoding)
        {
            Sha256Digest sha256Digest = new Sha256Digest();
            return DigestUtils.ComputeHashBytes(sha256Digest, data, encoding);
        }

        /// <summary>
        /// sha384加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha384(string data, Encoding encoding)
        {
            Sha384Digest sha384Digest = new Sha384Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(sha384Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha512加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha512(string data, Encoding encoding)
        {
            Sha512Digest sha512Digest = new Sha512Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(sha512Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
