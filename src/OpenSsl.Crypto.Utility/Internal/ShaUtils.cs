using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class ShaUtils
    {
        /// <summary>
        /// sha1摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns>摘要</returns>
        internal static byte[] Sha1(byte[] data)
        {
            Sha1Digest digest = new Sha1Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }

        /// <summary>
        /// sha224摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha224(byte[] data)
        {
            Sha224Digest digest = new Sha224Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }

        /// <summary>
        /// sha256摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha256(byte[] data)
        {
            Sha256Digest digest = new Sha256Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }

        /// <summary>
        /// sha384摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha384(byte[] data)
        {
            Sha384Digest digest = new Sha384Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }

        /// <summary>
        /// sha512摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns>摘要</returns>
        public static byte[] Sha512(byte[] data)
        {
            Sha512Digest digest = new Sha512Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }
    }
}