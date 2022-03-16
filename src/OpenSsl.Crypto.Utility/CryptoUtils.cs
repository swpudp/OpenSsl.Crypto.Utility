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
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] Sm4Encrypt(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.Encrypt(secretHex, plainText, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secretHex">密钥（Hex）</param>
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        public static string Sm4Decrypt(string secretHex, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.Decrypt(secretHex, cipherBytes, cipherMode, cipherPadding, iv);
        }

        #endregion

        #region RSA

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] RsaEncrypt(string publicKey, string plainText, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.Encrypt(publicKey, plainText, cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBytes">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static string RsaDecrypt(string privateKey, byte[] cipherBytes, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.Decrypt(privateKey, cipherBytes, cipherMode, padding);
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
