namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 加密/解密工具
    /// </summary>
    public static class CryptoUtils
    {
        #region AES

        #region 加密

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] AesEncryptToBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            return AesUtils.EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }


        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文十六进制字符</returns>
        public static string AesEncryptToHex(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.EncryptToHex(plainText, key, cipherMode, cipherPadding, iv, nonce);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>密文base64</returns>
        public static string AesEncryptToBase64(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.EncryptToBase64(plainText, key, cipherMode, cipherPadding, iv, nonce);
        }

        #endregion

        #region 解密


        /// <summary>
        /// AES解密
        /// </summary>
        /// <remarks>nonceBytes用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string AesDecryptFromBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null, byte[] nonceBytes = null)
        {
            return AesUtils.DecryptFromBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes, nonceBytes);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string AesDecryptFromHex(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.DecryptFromHex(cipher, key, cipherMode, cipherPadding, iv, nonce);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <remarks>nonce用于GCM加密模式</remarks>
        /// <returns>明文</returns>
        public static string AesDecryptFromBase64(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null, string nonce = null)
        {
            return AesUtils.DecryptFromBase64(cipher, key, cipherMode, cipherPadding, iv, nonce);
        }

        #endregion

        #endregion

        #region SM4

        #region 加密

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainText">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>十六进制字符串密文</returns>
        public static string Sm4EncryptToHex(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.EncryptToHex(secretHex, plainText, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainText">明文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>Base64密文</returns>
        public static string Sm4EncryptToBase64(string secretHex, string plainText, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.EncryptToBase64(secretHex, plainText, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="plainBytes">明文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] Sm4EncryptToBytes(string secretHex, byte[] plainBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.EncryptToBytes(secretHex, plainBytes, cipherMode, cipherPadding, iv);
        }

        #endregion

        #region 解密

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="cipher">从十六进制字符串密文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        public static string Sm4DecryptFromBase64(string secretHex, string cipher, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.DecryptFromBase64(secretHex, cipher, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secretHex">十六进制密钥（128位）</param>
        /// <param name="cipherBytes">密文字节</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文字节数组</returns>
        public static string Sm4DecryptFromBytes(string secretHex, byte[] cipherBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.DecryptFromBytes(secretHex, cipherBytes, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="secret">十六进制密钥（128位）</param>
        /// <param name="cipher">十六进制字符串密文</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="cipherPadding">数据填充方式</param>
        /// <param name="iv">密钥偏移量</param>
        /// <remarks>密钥长度必须是128位</remarks>
        /// <returns>明文</returns>
        public static string Sm4DecryptFromHex(string secret, string cipher, CipherMode cipherMode, CipherPadding cipherPadding, byte[] iv = null)
        {
            return SmUtils.DecryptFromHex(secret, cipher, cipherMode, cipherPadding, iv);
        }

        #endregion

        #endregion

        #region RSA

        #region 加密

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文hex</returns>
        public static string RsaEncryptToHex(string plainText, string publicKey, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.EncryptToHex(plainText, publicKey, cipherMode, padding);
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文base64</returns>
        public static string RsaEncryptToBase64(string plainText, string publicKey, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.EncryptToBase64(plainText, publicKey, cipherMode, padding);
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plainBytes">明文</param>
        /// <param name="publicKeyBytes">密钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] RsaEncryptToBytes(byte[] plainBytes, byte[] publicKeyBytes, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.EncryptToBytes(plainBytes, publicKeyBytes, cipherMode, padding);
        }

        #endregion

        #region 解密

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBytes">密文base64</param>
        /// <param name="privateKeyBytes">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static string RsaDecryptFromBytes(byte[] cipherBytes, byte[] privateKeyBytes, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.DecryptFromBytes(cipherBytes, privateKeyBytes, cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherHex">密文hex</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static string RsaDecryptFromHex(string cipherHex, string privateKey, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.DecryptFromHex(cipherHex, privateKey, cipherMode, padding);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherBase64">密文base64</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="cipherMode">加密模式</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文</returns>
        public static string RsaDecryptFromBase64(string cipherBase64, string privateKey, CipherMode cipherMode, CipherPadding padding)
        {
            return RsaUtils.DecryptFromBase64(cipherBase64, privateKey, cipherMode, padding);
        }

        #endregion

        #endregion

        #region DES

        #region 加密

        /// <summary>
        /// 加密（字节数组）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] DesEncryptToBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密（十六进制字符）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文十六进制字符</returns>
        public static string DesEncryptToHex(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return DesUtils.EncryptToHex(plainText, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 加密（base64）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文base64</returns>
        public static string DesEncryptToBase64(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return DesUtils.EncryptToBase64(plainText, key, cipherMode, cipherPadding, iv);
        }

        #endregion

        #region 解密

        /// <summary>
        /// DES解密（Base64）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string DesDecryptFromBase64(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return DesUtils.DecryptFromBase64(cipher, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 解密（十六进制）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string DesDecryptFromHex(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return DesUtils.DecryptFromHex(cipher, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 解密（字节数组）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string DesDecryptFromBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return DesUtils.DecryptFromBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }

        #endregion

        #endregion

        #region Triple DES

        #region 加密

        /// <summary>
        /// 加密（字节数组）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文字节数组</returns>
        public static byte[] TripleDesEncryptToBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.EncryptToBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }

        /// <summary>
        /// 加密（十六进制字符）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文十六进制字符</returns>
        public static string TripleDesEncryptToHex(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return TripleDesUtils.EncryptToHex(plainText, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 加密（base64）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>密文base64</returns>
        public static string TripleDesEncryptToBase64(string plainText, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return TripleDesUtils.EncryptToBase64(plainText, key, cipherMode, cipherPadding, iv);
        }

        #endregion

        #region 解密

        /// <summary>
        /// DES解密（Base64）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string TripleDesDecryptFromBase64(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return TripleDesUtils.DecryptFromBase64(cipher, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 解密（十六进制）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string TripleDesDecryptFromHex(string cipher, string key, CipherMode cipherMode, CipherPadding cipherPadding, string iv = null)
        {
            return TripleDesUtils.DecryptFromHex(cipher, key, cipherMode, cipherPadding, iv);
        }

        /// <summary>
        /// 解密（字节数组）
        /// </summary>
        /// <remarks>iv长度是8</remarks>
        /// <returns>明文</returns>
        public static string TripleDesDecryptFromBytes(byte[] plainBytes, byte[] keyBytes, CipherMode cipherMode, CipherPadding cipherPadding, byte[] ivBytes = null)
        {
            return TripleDesUtils.DecryptFromBytes(plainBytes, keyBytes, cipherMode, cipherPadding, ivBytes);
        }

        #endregion

        #endregion
    }
}
