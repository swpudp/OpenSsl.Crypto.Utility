using System.Text;
using System;
using OpenSsl.Crypto.Utility;

namespace UnitTests
{
    /// <summary>
    /// 自定义编码器
    /// </summary>
    internal static class SimpleCoder
    {
        /// <summary>
        /// 编码签名结果
        /// </summary>
        /// <param name="signBytes"></param>
        /// <returns></returns>
        public static string EncodeBytes(byte[] signBytes)
        {
            string hex = HexUtils.ToHexString(signBytes);
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(hex));
        }

        /// <summary>
        /// 解码签名结果
        /// </summary>
        /// <param name="sign"></param>
        /// <returns></returns>
        public static byte[] DecodeBytes(string sign)
        {
            byte[] signBytes = Convert.FromBase64String(sign);
            return HexUtils.DecodeBytes(signBytes);
        }
    }
}
