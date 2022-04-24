using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// sm2格式签名
    /// </summary>
    internal class Sm2Signature : Asn1Encodable
    {
        private readonly DerInteger _r;
        private readonly DerInteger _s;

        public Sm2Signature(byte[] signBytes)
        {
            if (signBytes == null)
            {
                throw new ArgumentNullException("Sm2Signature signBytes missing");
            }

            if (signBytes.Length != 64)
            {
                throw new ArgumentNullException("Sm2Signature signBytes required length=64");
            }

            _r = new DerInteger(Arrays.CopyOfRange(signBytes, 0, 32));
            _s = new DerInteger(Arrays.CopyOfRange(signBytes, 32, 64));
        }

        public Sm2Signature(DerInteger r, DerInteger s)
        {
            _r = r;
            _s = s;
        }

        public static Sm2Signature GetInstance(object o)
        {
            if (o == null)
            {
                throw new ArgumentNullException("Sm2Signature missing object for getInstance");
            }
            if (o is Sm2Signature sign)
            {
                return sign;
            }
            Asn1Sequence seq = Asn1Sequence.GetInstance(o);
            IEnumerator e = seq.GetEnumerator();

            e.MoveNext();
            DerInteger r = DerInteger.GetInstance(e.Current);

            e.MoveNext();
            DerInteger s = DerInteger.GetInstance(e.Current);

            return new Sm2Signature(r, s);
        }

        public byte[] GetRawBytes()
        {
            byte[] dest = new byte[64];
            System.Array.Copy(_r.PositiveValue.ToByteArrayUnsigned(), 0, dest, 0, 32);
            System.Array.Copy(_s.PositiveValue.ToByteArrayUnsigned(), 0, dest, 32, 32);
            return dest;
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector
            {
                _r,
                _s
            };
            return new DerSequence(v);
        }
    }
}
