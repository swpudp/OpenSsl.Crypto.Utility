using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility
{
    public static class HexUtils
    {
        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        /// <param name="hexValue"></param>
        /// <returns></returns>
        public static byte[] ToByteArray(string hexValue)
        {
            return Hex.Decode(hexValue);
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

        /// <summary>
        /// 对字节数据进行编码
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        /// <remarks>返回长度为原来2倍</remarks>
        public static byte[] EncodeByteArray(byte[] value)
        {
            return Hex.Encode(value);
        }
    }
}
