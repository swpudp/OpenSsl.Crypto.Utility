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
        /// <param name="encoding">编码</param>
        /// <returns></returns>
        internal static string Digest(string data, Encoding encoding)
        {
            MD5Digest digest = new MD5Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }

        /// <summary>
        /// MD5摘要计算
        /// </summary>
        /// <param name="data">待计算内容</param>
        /// <param name="encoding">编码</param>
        /// <returns></returns>
        internal static string Digest(byte[] data, Encoding encoding)
        {
            MD5Digest digest = new MD5Digest();
            var hashBytes = digest.ComputeHashBytes(data);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
