using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class DigestExtension
    {
        /// <summary>
        /// 计数器ct
        /// </summary>
        private static readonly byte[] Ct = {0, 0, 0, 1};

        /// <summary>
        /// 计算Hash字节
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="data"></param>
        /// <param name="forKdf"></param>
        /// <returns></returns>
        internal static byte[] ComputeHashBytes(this IDigest digest, byte[] data, bool forKdf)
        {
            var hashBytes = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(data, 0, data.Length);
            if (forKdf)
            {
                digest.BlockUpdate(Ct, 0, Ct.Length);
            }

            digest.DoFinal(hashBytes, 0);
            return hashBytes;
        }

        /// <summary>
        /// 计算Hash字节
        /// </summary>
        /// <param name="hmac"></param>
        /// <param name="key"></param>
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

        /// <summary>
        /// 计算Hash字节
        /// </summary>
        /// <param name="hmac"></param>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        internal static byte[] ComputeHashBytes(this IMac hmac, string key, byte[] data, Encoding encoding)
        {
            hmac.Init(new KeyParameter(encoding.GetBytes(key)));
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.DoFinal(resBuf, 0);
            return resBuf;
        }
    }
}