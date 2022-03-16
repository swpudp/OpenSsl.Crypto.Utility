using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility
{
    internal static class ShaUtils
    {
        /// <summary>
        /// sha1摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha1(string data, Encoding encoding)
        {
            Sha1Digest digest = new Sha1Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha1摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        internal static string Sha1(byte[] data, Encoding encoding)
        {
            Sha1Digest digest = new Sha1Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha224摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha224(string data, Encoding encoding)
        {
            Sha224Digest digest = new Sha224Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha224摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha224(byte[] data, Encoding encoding)
        {
            Sha224Digest digest = new Sha224Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha256摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha256(string data, Encoding encoding)
        {
            Sha256Digest digest = new Sha256Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha256摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha256(byte[] data, Encoding encoding)
        {
            Sha256Digest digest = new Sha256Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha384摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha384(string data, Encoding encoding)
        {
            Sha384Digest digest = new Sha384Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha384摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha384(byte[] data, Encoding encoding)
        {
            Sha384Digest digest = new Sha384Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha512摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha512(string data, Encoding encoding)
        {
            Sha512Digest digest = new Sha512Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// sha512摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns>摘要</returns>
        public static string Sha512(byte[] data, Encoding encoding)
        {
            Sha512Digest digest = new Sha512Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
