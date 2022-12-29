using System.Collections.Generic;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class AlgorithmUtils
    {
        /// <summary>
        /// 加密模式
        /// </summary>
        private static readonly Dictionary<CipherMode, string> CipherModes = new Dictionary<CipherMode, string>
        {
            [CipherMode.NONE] = "NONE",
            [CipherMode.ECB] = "ECB",
            [CipherMode.CBC] = "CBC",
            [CipherMode.CCM] = "CCM",
            [CipherMode.CFB] = "CFB",
            [CipherMode.CTR] = "CTR",
            [CipherMode.CTS] = "CTS",
            [CipherMode.EAX] = "EAX",
            [CipherMode.GCM] = "GCM",
            [CipherMode.GOFB] = "GOFB",
            [CipherMode.OCB] = "OCB",
            [CipherMode.OFB] = "OFB",
            [CipherMode.OPENPGPCFB] = "OPENPGPCFB",
            [CipherMode.SIC] = "SIC"
        };

        /// <summary>
        /// 数据填充方式
        /// </summary>
        private static readonly Dictionary<CipherPadding, string> CipherPaddings = new Dictionary<CipherPadding, string>
        {
            [CipherPadding.NONE] = "NoPadding",
            [CipherPadding.RAW] = string.Empty,
            [CipherPadding.ISO10126] = "ISO10126d2Padding",
            [CipherPadding.ISO7816d4] = "ISO7816_4Padding",
            [CipherPadding.ISO97961] = "ISO9796_1Padding",
            [CipherPadding.OAEP] = "OAEPPadding",
            [CipherPadding.OAEPWITHMD5ANDMGF1] = "OAEPWITHMD5ANDMGF1PADDING",
            [CipherPadding.OAEPWITHSHA1ANDMGF1] = "OAEPWITHSHA1ANDMGF1PADDING",
            [CipherPadding.OAEPWITHSHA224ANDMGF1] = "OAEPWITHSHA224ANDMGF1PADDING",
            [CipherPadding.OAEPWITHSHA256ANDMGF1] = "OAEPWITHSHA256ANDMGF1PADDING",
            [CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA1] = "OAEPWITHSHA256ANDMGF1WITHSHA1PADDING",
            [CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA256] = "OAEPWITHSHA256ANDMGF1WITHSHA256PADDING",
            [CipherPadding.OAEPWITHSHA384ANDMGF1] = "OAEPWITHSHA384ANDMGF1PADDING",
            [CipherPadding.OAEPWITHSHA512ANDMGF1] = "OAEPWITHSHA512ANDMGF1PADDING",
            [CipherPadding.PKCS1] = "PKCS1PADDING",
            [CipherPadding.PKCS5] = "PKCS5PADDING",
            [CipherPadding.PKCS7] = "PKCS7PADDING",
            [CipherPadding.TBC] = "TBCPADDING",
            [CipherPadding.WITHCTS] = "WITHCTS",
            [CipherPadding.X923] = "X923PADDING",
            [CipherPadding.ZEROBYTE] = "ZEROBYTEPADDING"
        };

        /// <summary>
        /// 获取加密算法名称
        /// </summary>
        /// <param name="algorithmName"></param>
        /// <param name="cipherMode"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        internal static string GetCipherAlgorithm(string algorithmName, CipherMode cipherMode, CipherPadding padding)
        {
            return $"{algorithmName}/{GetCipherMode(cipherMode)}/{GetCipherPadding(padding)}";
        }

        /// <summary>
        /// 获取加密模式文本
        /// </summary>
        /// <param name="cipherMode"></param>
        /// <returns></returns>
        /// <exception cref="System.NotSupportedException"></exception>
        private static string GetCipherMode(CipherMode cipherMode)
        {
            return CipherModes.TryGetValue(cipherMode, out var cipher) ? cipher : throw new System.NotSupportedException(nameof(cipherMode));
        }

        /// <summary>
        /// 获取填充方式
        /// </summary>
        /// <param name="cipherPadding"></param>
        /// <returns></returns>
        /// <exception cref="System.NotSupportedException"></exception>
        private static string GetCipherPadding(CipherPadding cipherPadding)
        {
            return CipherPaddings.TryGetValue(cipherPadding, out var padding) ? padding : throw new System.NotSupportedException(nameof(cipherPadding));
        }
    }
}
