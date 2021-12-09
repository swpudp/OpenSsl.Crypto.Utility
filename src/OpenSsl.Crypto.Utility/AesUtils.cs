using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Linq;
using System.Text;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// AES加密工具 todo 待单元测试
    /// </summary>
    public static class AesUtils
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] EncryptToBytes(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, byte[] nonceBytes, CipherMode cipherMode, CipherPadding cipherPadding)
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
            if (ivBytes != null && ivBytes.Any(f => f > 0))
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
        public static string DecryptFromBytes(byte[] plainBytes, byte[] keyBytes, byte[] ivBytes, byte[] nonceBytes, CipherMode cipherMode, CipherPadding cipherPadding)
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
        public static string EncryptToHex(string plainText, string key, string iv, string nonce, CipherMode cipherMode, CipherPadding cipherPadding)
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
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, ivBytes, nonceBytes, cipherMode, cipherPadding);
            return Hex.ToHexString(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string DecryptFromHex(string cipher, string key, string iv, string nonce, CipherMode cipherMode, CipherPadding cipherPadding)
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
            return DecryptFromBytes(cipherBytes, keyBytes, ivBytes, nonceBytes, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文base64</returns>
        public static string EncryptToBase64(string plainText, string key, string iv, string nonce, CipherMode cipherMode, CipherPadding cipherPadding)
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
            byte[] cipherBytes = EncryptToBytes(plainBytes, keyBytes, ivBytes, nonceBytes, cipherMode, cipherPadding);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string DecryptFromBase64(string cipher, string key, string iv, string nonce, CipherMode cipherMode, CipherPadding cipherPadding)
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
            return DecryptFromBytes(cipherBytes, keyBytes, ivBytes, nonceBytes, cipherMode, cipherPadding);
        }
    }
}
