using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    internal static class ShaUtils
    {
        /// <summary>
        /// sha1加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        internal static string Sha1(string data, Encoding encoding)
        {
            Sha1Digest digest = new Sha1Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
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
            Sha224Digest digest = new Sha224Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
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
            Sha256Digest digest = new Sha256Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
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
            Sha256Digest digest = new Sha256Digest();
            return digest.ComputeHashBytes(data, encoding);
        }

        /// <summary>
        /// sha384加密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="encoding">编码</param>
        /// <returns>密文</returns>
        public static string Sha384(string data, Encoding encoding)
        {
            Sha384Digest digest = new Sha384Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
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
            Sha512Digest digest = new Sha512Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
