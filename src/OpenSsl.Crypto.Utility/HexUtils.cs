using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility
{
    public static class HexUtils
    {
        /// <summary>
        /// 解密十六进制字符串
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] DecodeHex(string value)
        {
            return Hex.Decode(value);
        }

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] DecodeBytes(byte[] value)
        {
            return Hex.Decode(value);
        }

        /// <summary>
        /// 将字节数组转化为十六进制字符
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToHexString(byte[] data)
        {
            return Hex.ToHexString(data);
        }
    }
}
