using System;
using System.Text;
using OpenSsl.Crypto.Utility.Internal;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 加密/解密工具
    /// </summary>
    public static class CryptoUtils
    {
        #region AES

        /// <summary>
        /// AES加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] AesEncrypt(string key, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.Encrypt(key, plainText, cipherMode, cipherPadding, iv, nonce);
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] AesEncrypt(byte[] keyBytes, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            return AesUtils.Encrypt(keyBytes, plainText, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string AesDecrypt(string key, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.Decrypt(key, cipherBytes, cipherMode, cipherPadding, iv, nonce);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string AesDecrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            return AesUtils.Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        #endregion

        #region SM4

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">密钥（Hex）</param>
        /// <param name="plainText">明文</param>
        /// <param name="encoding">编码方式</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] Sm4Encrypt(string secretHex, string plainText, Encoding encoding, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] keyBytes = HexUtils.ToByteArray(secretHex);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = encoding.GetBytes(iv);
            }

            byte[] cipherBytes = SmUtils.Encrypt(keyBytes, encoding.GetBytes(plainText), cipherMode, cipherPadding, ivBytes);
            return (cipherBytes);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="keyBytes">密钥（Hex）</param>
        /// <param name="plainBytes">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] Sm4Encrypt(byte[] keyBytes, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            byte[] cipherBytes = SmUtils.Encrypt(keyBytes, plainBytes, cipherMode, cipherPadding, iv);
            return cipherBytes;
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="keyBytes">密钥</param>
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        public static byte[] Sm4Decrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="cipherBytes">密文</param>
        /// <param name="encoding">文本编码</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        public static string Sm4Decrypt(string key, byte[] cipherBytes, Encoding encoding, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            byte[] keyBytes = HexUtils.ToByteArray(key);
            byte[] ivBytes = null;
            if (!string.IsNullOrWhiteSpace(iv))
            {
                ivBytes = encoding.GetBytes(iv);
            }

            byte[] plainBytes = SmUtils.Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes);
            return encoding.GetString(plainBytes);
        }

        #endregion

        #region RSA

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="encoding">文本编码格式</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] RsaEncrypt(string publicKey, string plainText, Encoding encoding, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] cipher = RsaUtils.Encrypt(publicKeyBytes, encoding.GetBytes(plainText), cipherMode, padding);
            return (cipher);
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainTextBytes">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] RsaEncrypt(byte[] publicKey, byte[] plainTextBytes, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.Encrypt(publicKey, (plainTextBytes), cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static byte[] RsaDecrypt(byte[] privateKey, byte[] cipherBytes, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.Decrypt(privateKey, cipherBytes, cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBytes">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">文字编码方式</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static string RsaDecrypt(string privateKey, byte[] cipherBytes, Encoding encoding, CipherMode cipherMode, CipherPadding padding)
        {
            byte[] privateKeyBytes = encoding.GetBytes(privateKey);
            byte[] plainBytes = RsaUtils.Decrypt(privateKeyBytes, cipherBytes, cipherMode, padding);
            return encoding.GetString(plainBytes);
        }

        #endregion

        #region DES

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] DesEncrypt(string key, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.Encrypt(key, plainText, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] DesEncrypt(byte[] keyBytes, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.Encrypt(keyBytes, plainText, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// DES解密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>明文</returns>
        public static string DesDecrypt(string key, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.Decrypt(key, cipherBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>明文</returns>
        public static string DesDecrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes);
        }

        #endregion

        #region Triple DES

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] TripleDesEncrypt(byte[] keyBytes, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.Encrypt(keyBytes, plainText, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>key为16或24字节，iv为8字节</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] TripleDesEncrypt(string key, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.Encrypt(key, plainText, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>key为16或24字节，iv为8字节</remarks>
        /// <returns>明文</returns>
        public static string TripleDesDecrypt(string key, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.Decrypt(key, cipherBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>iv为8字节</remarks>
        /// <returns>明文</returns>
        public static string TripleDesDecrypt(byte[] keyBytes, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.Decrypt(keyBytes, cipherBytes, cipherMode, cipherPadding, ivBytes);
        }

        #endregion
    }
}