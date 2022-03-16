using System;
using System.Text;
using OpenSsl.Crypto.Utility;
using Org.BouncyCastle.Asn1;

namespace UnitTests
{
    /// <summary>
    /// 自定义编码器
    /// </summary>
    internal static class SimpleCoder
    {

        /// <summary>
        /// 编码
        /// </summary>
        /// <param name="valueBytes"></param>
        /// <returns></returns>
        public static string EncodeBytes(byte[] valueBytes)
        {
            string hex = HexUtils.ToHexString(valueBytes); ;
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(hex));
        }

        /// <summary>
        /// 解码
        /// </summary>
        /// <param name="valueStr"></param>
        /// <returns></returns>
        public static byte[] DecodeBytes(string valueStr)
        {
            byte[] valueBytes = Convert.FromBase64String(valueStr);
            string value = Encoding.UTF8.GetString(valueBytes);
            return HexUtils.ToByteArray(value);
        }

        /// <summary>
        /// 编码
        /// </summary>
        /// <param name="signBytes"></param>
        /// <returns></returns>
        public static string EncodeDERBytes(byte[] signBytes)
        {
            byte[] data = DecodeDERSignature(signBytes);
            return HexUtils.ToHexString(data);
        }

        /// <summary>
        /// 解码
        /// </summary>
        /// <param name="sign"></param>
        /// <returns></returns>
        public static byte[] DecodeDERBytes(string sign)
        {
            byte[] signBytes = HexUtils.ToByteArray(sign);
            return EncodeDERSignature(signBytes);
        }

        private static byte[] EncodeDERSignature(byte[] signature)
        {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            Array.Copy(signature, 0, r, 0, 32);
            Array.Copy(signature, 32, s, 0, 32);
            Asn1EncodableVector vector = new Asn1EncodableVector();
            vector.Add(new DerInteger(r));
            vector.Add(new DerInteger(s));
            return new DerSequence(vector).GetEncoded();
        }

        /// <summary>
        /// 解码
        /// </summary>
        /// <param name="signature"></param>
        /// <returns></returns>
        private static byte[] DecodeDERSignature(byte[] signature)
        {
            Asn1InputStream stream = new Asn1InputStream(signature);
            Asn1Sequence primitive = (Asn1Sequence)stream.ReadObject();
            var enumerator = primitive.GetEnumerator();

            enumerator.MoveNext();
            //var R = DerInteger.GetInstance(enumerator.Current).Value;
            var R = ((DerInteger)enumerator.Current).Value;

            enumerator.MoveNext();
            //var S = DerInteger.GetInstance(enumerator.Current).Value;
            var S = ((DerInteger)enumerator.Current).Value;

            byte[] bytes = new byte[64];
            byte[] r = Format(R.ToByteArray());
            byte[] s = Format(S.ToByteArray());
            Array.Copy(r, 0, bytes, 0, 32);
            Array.Copy(s, 0, bytes, 32, 32);
            return bytes;
        }

        /// <summary>
        /// 格式
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static byte[] Format(byte[] value)
        {
            if (value.Length == 32)
            {
                return value;
            }
            byte[] bytes = new byte[32];
            if (value.Length > 32)
            {
                Array.Copy(value, value.Length - 32, bytes, 0, 32);
            }
            else
            {
                Array.Copy(value, 0, bytes, 32 - value.Length, value.Length);
            }
            return bytes;
        }
    }
}
