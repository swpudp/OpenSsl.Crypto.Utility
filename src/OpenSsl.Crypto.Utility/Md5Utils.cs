using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    internal static class Md5Utils
    {
        /// <summary>
        /// md5加密处理
        /// </summary>
        /// <param name="data">待加密字符</param>
        /// <param name="encoding">编码</param>
        /// <returns></returns>
        internal static string Digest(string data, Encoding encoding)
        {
            MD5Digest digest = new MD5Digest();
            var hashBytes = digest.ComputeHashBytes(data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
