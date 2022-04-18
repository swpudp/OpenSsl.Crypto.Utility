using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class Md5Utils
    {
        /// <summary>
        /// MD5摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <returns></returns>
        internal static byte[] Digest(byte[] data)
        {
            MD5Digest digest = new MD5Digest();
            var hashBytes = digest.ComputeHashBytes(data, false);
            return hashBytes;
        }
    }
}