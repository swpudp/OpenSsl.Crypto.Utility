using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    internal static class DigestExtension
    {
        /// <summary>
        /// 计算Hash字节
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        internal static byte[] ComputeHashBytes(this IDigest digest, string data, Encoding encoding)
        {
            var hashBytes = new byte[digest.GetDigestSize()];
            var bs = encoding.GetBytes(data);
            digest.BlockUpdate(bs, 0, bs.Length);
            digest.DoFinal(hashBytes, 0);
            return hashBytes;
        }

        /// <summary>
        /// 计算Hash字节
        /// </summary>
        /// <param name="hmac"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        internal static byte[] ComputeHashBytes(this IMac hmac, string key, string data, Encoding encoding)
        {
            byte[] m = encoding.GetBytes(data);
            hmac.Init(new KeyParameter(encoding.GetBytes(key)));
            hmac.BlockUpdate(m, 0, m.Length);
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.DoFinal(resBuf, 0);
            return resBuf;
        }
    }
}
