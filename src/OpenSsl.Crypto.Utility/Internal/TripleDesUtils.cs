using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// Triple DES加密工具
    /// </summary>
    internal static class TripleDesUtils
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(string key, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            return EncryptToBytes(keyBytes, plainBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(byte[] keyBytes, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            return EncryptToBytes(keyBytes, plainBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        private static byte[] EncryptToBytes(byte[] keyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("DESEDE", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, ivBytes);
            cipher.Init(true, parameters);
            return cipher.DoFinal(plainBytes);
        }

        /// <summary>
        /// 获取加密参数
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns></returns>
        private static ICipherParameters GetCipherParameters(byte[] keyBytes, byte[] ivBytes)
        {
            if (ivBytes != null)
            {
                return new ParametersWithIV(new DesParameters(keyBytes), ivBytes);
            }
            return new KeyParameter(keyBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>明文</returns>
        internal static string Decrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("DESEDE", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, ivBytes);
            cipher.Init(false, parameters);
            byte[] output = cipher.DoFinal(cipherBytes);
            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>明文</returns>
        internal static string Decrypt(string key, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            return Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes);
        }
    }
}
