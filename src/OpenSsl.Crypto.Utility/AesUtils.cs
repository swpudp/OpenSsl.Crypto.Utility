using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// AES加密工具
    /// </summary>
    internal static class AesUtils
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] EncryptToBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("AES", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, nonceBytes, ivBytes, cipherMode);
            cipher.Init(true, parameters);
            return cipher.DoFinal(plainBytes);
        }

        /// <summary>
        /// 获取加密参数
        /// </summary>
        /// <returns></returns>
        private static ICipherParameters GetCipherParameters(byte[] keyBytes, byte[] nonceBytes, byte[] ivBytes, CipherMode cipherMode)
        {
            KeyParameter keyParameter = new KeyParameter(keyBytes);
            if (cipherMode == CipherMode.GCM)
            {
                return new AeadParameters(keyParameter, 128, ivBytes, nonceBytes);
            }
            if (ivBytes != null)
            {
                return new ParametersWithIV(keyParameter, ivBytes);
            }
            return keyParameter;
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("AES", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, nonceBytes, ivBytes, cipherMode);
            cipher.Init(false, parameters);
            byte[] output = cipher.DoFinal(plainBytes);
            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文十六进制字符</returns>
        internal static string EncryptToHex(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] nonceBytes = null;
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                nonceBytes = Encoding.UTF8.GetBytes(nonce);
            }
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
            return Hex.ToHexString(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromHex(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            byte[] cipherBytes = Hex.Decode(cipher);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] nonceBytes = null;
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                nonceBytes = Encoding.UTF8.GetBytes(nonce);
            }
            return DecryptFromBytes(cipherBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文base64</returns>
        internal static string EncryptToBase64(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] nonceBytes = null;
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                nonceBytes = Encoding.UTF8.GetBytes(nonce);
            }
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        internal static string DecryptFromBase64(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipher);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }
            byte[] nonceBytes = null;
            if (!string.IsNullOrWhiteSpace(nonce))
            {
                nonceBytes = Encoding.UTF8.GetBytes(nonce);
            }
            return DecryptFromBytes(cipherBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }
    }
}
