using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// Triple DES加密工具
    /// </summary>
    internal static class TripleDesUtils
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] EncryptToBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
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
        /// <remarks>iv长度是8</remarks>
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
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("DESEDE", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, ivBytes);
            cipher.Init(false, parameters);
            byte[] output = cipher.DoFinal(plainBytes);
            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文十六进制字符</returns>
        internal static string EncryptToHex(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
            return Hex.ToHexString(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromHex(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] cipherBytes = Hex.Decode(cipher);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            return DecryptFromBytes(cipherBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文base64</returns>
        internal static string EncryptToBase64(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromBase64(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipher);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            return DecryptFromBytes(cipherBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }
    }
}
