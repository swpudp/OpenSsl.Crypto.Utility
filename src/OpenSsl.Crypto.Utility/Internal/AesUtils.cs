using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// AES加密工具
    /// </summary>
    internal static class AesUtils
    {
        #region 加密

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(string key, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
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
            return EncryptToBytes(keyBytes, plainBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        internal static byte[] Encrypt(byte[] keyBytes, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            return EncryptToBytes(keyBytes, plainBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        private static byte[] EncryptToBytes(byte[] keyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("AES", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, nonceBytes, ivBytes, cipherMode);
            cipher.Init(true, parameters);
            return cipher.DoFinal(plainBytes);
        }

        #endregion

        #region 解密

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string Decrypt(byte[] keyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            string algorithm = AlgorithmUtils.GetCipherAlgorithm("AES", cipherMode, cipherPadding);
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            ICipherParameters parameters = GetCipherParameters(keyBytes, nonceBytes, ivBytes, cipherMode);
            cipher.Init(false, parameters);
            byte[] output = cipher.DoFinal(plainBytes);
            return Encoding.UTF8.GetString(output);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        internal static string Decrypt(string key, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
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
            return Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        #endregion

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
    }
}
