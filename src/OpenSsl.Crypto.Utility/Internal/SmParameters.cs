using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class SmParameters
    {
        /// <summary>
        /// EC参数
        /// </summary>
        internal static readonly X9ECParameters Sm2EcParameters = GMNamedCurves.GetByName("sm2p256v1");

        /// <summary>
        /// EC Domain参数
        /// </summary>
        internal static readonly ECDomainParameters DomainParameters = new ECDomainParameters(Sm2EcParameters.Curve, Sm2EcParameters.G, Sm2EcParameters.N);

        internal static readonly DerObjectIdentifier sm2Data = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.1");

        internal static readonly DerObjectIdentifier sm2SignedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.2");

        //private static readonly DerObjectIdentifier sm2EnvelopedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.3");
        //private static readonly DerObjectIdentifier sm2SignedAndEnvelopedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.4");
        //private static readonly DerObjectIdentifier sm2EncryptedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.5");
        //private static readonly DerObjectIdentifier sm2KeyAgreementInfo = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.6");
        internal static readonly DerInteger signInfoVersion = new DerInteger(1L);
        internal static readonly DerInteger signedDataVersion = new DerInteger(1L);
        internal static readonly DerInteger p12Version = new DerInteger(1L);
    }
}