using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    public static class Md5Utils
    {
        /// <summary>
        /// md5加密处理
        /// </summary>
        /// <param name="data">待加密字符</param>
        /// <param name="encoding">编码</param>
        /// <returns></returns>
        public static string Encrypt(string data, Encoding encoding)
        {
            MD5Digest mD5Digest = new MD5Digest();
            var hashBytes = DigestUtils.ComputeHashBytes(mD5Digest, data, encoding);
            return encoding.GetString(Hex.Encode(hashBytes));
        }
    }
}
