using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class SmPkcs7Utils
    {
        private static readonly DerObjectIdentifier sm2Data = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.1");
        private static readonly DerObjectIdentifier sm2SignedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.2");
        private static readonly DerObjectIdentifier sm2EnvelopedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.3");
        private static readonly DerObjectIdentifier sm2SignedAndEnvelopedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.4");
        private static readonly DerObjectIdentifier sm2EncryptedData = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.5");
        private static readonly DerObjectIdentifier sm2KeyAgreementInfo = new DerObjectIdentifier("1.2.156.10197.6.1.4.2.6");
        private static readonly DerInteger signInfoVersion = new DerInteger(1L);
        private static readonly DerInteger signedDataVersion = new DerInteger(1L);
        private static readonly DerInteger p12Version = new DerInteger(1L);


        /// <summary>
        /// pkcs7带原文签名
        /// </summary>
        /// <returns></returns>
        internal static byte[] Package(byte[] signature, X509Certificate x509Cert, byte[] sourceData)
        {
            byte[] signData = GetSignData(new[] { x509Cert }, signature, sourceData);
            CmsSignedData signedData = new CmsSignedData(signData);
            byte[] encoding = signedData.GetEncoded(Asn1Encodable.Der);
            return encoding;
        }

        /// <summary>
        /// pkcs7带原文验签
        /// </summary>
        /// <param name="sourceData">原文字节</param>
        /// <param name="signature">签名字节</param>
        /// <param name="func">验证函数</param>
        /// <returns></returns>
        /// <exception cref="NotSupportedException"></exception>
        internal static bool UnPackage(byte[] sourceData, byte[] signature, Func<byte[], byte[], byte[], bool, bool> func)
        {
            CmsSignedDataParser sp = new CmsSignedDataParser(signature);
            sp.GetSignedContent().Drain();

            IX509Store certStore = sp.GetCertificates("Collection");
            SignerInformationStore signers = sp.GetSignerInfos();

            foreach (SignerInformation signerInfo in signers.GetSigners())
            {
                ICollection certCollection = certStore.GetMatches(signerInfo.SignerID);
                IEnumerator certEnum = certCollection.GetEnumerator();
                certEnum.MoveNext();
                if (!(certEnum.Current is X509Certificate cert))
                {
                    throw new NotSupportedException();
                }

                byte[] encryptedDigest = signerInfo.GetSignature();
                Sm2Signature sm2Signature = Sm2Signature.GetInstance(encryptedDigest);
                byte[] signBytes = sm2Signature.GetRawBytes();

                byte[] publicKey = SmCertUtils.GetPublicKey(cert.GetPublicKey());
                bool verify = func(publicKey, sourceData, signBytes, true);
                if (!verify)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// 获取p7签名数据
        /// </summary>
        /// <param name="certs"></param>
        /// <param name="signature"></param>
        /// <param name="sourceData"></param>
        /// <returns></returns>
        private static byte[] GetSignData(X509Certificate[] certs, byte[] signature, byte[] sourceData)
        {
            BigInteger sn = certs[0].SerialNumber;
            X509Name issuer = certs[0].IssuerDN;
            IssuerAndSerialNumber issuerAndSn = new IssuerAndSerialNumber(issuer, sn);
            SignerInfo signerInfo = GetSignerInfo(signature, issuerAndSn);
            DerOctetString derSourceData = new DerOctetString(sourceData);
            ContentInfo sourceContentInfo = new ContentInfo(sm2Data, derSourceData);
            AlgorithmIdentifier digestAlgIdentifier = new AlgorithmIdentifier(GMObjectIdentifiers.sm3, DerNull.Instance);
            Asn1EncodableVector derV = new Asn1EncodableVector
            {
                digestAlgIdentifier
            };
            Asn1Set digestAlgorithmSets = new DerSet(derV);
            derV = new Asn1EncodableVector
            {
                signerInfo
            };
            Asn1Set signerInfos = new DerSet(derV);
            Asn1EncodableVector v = new Asn1EncodableVector();
            foreach (X509Certificate cert in certs)
            {
                v.Add(Asn1Object.FromByteArray(cert.GetEncoded()));
            }

            Asn1Set setCert = new BerSet(v);
            SignedData signedData = new SignedData(signedDataVersion, digestAlgorithmSets, sourceContentInfo, setCert, null, signerInfos);
            ContentInfo contentInfo = new ContentInfo(sm2SignedData, signedData);
            byte[] contentBytes = contentInfo.GetDerEncoded();
            return contentBytes;
        }

        /// <summary>
        /// 获取sm2签名数据
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="issuerAndSn"></param>
        /// <returns></returns>
        private static SignerInfo GetSignerInfo(byte[] signature, IssuerAndSerialNumber issuerAndSn)
        {
            Sm2Signature signData = new Sm2Signature(signature);
            AlgorithmIdentifier digestAlgIdentifier = new AlgorithmIdentifier(GMObjectIdentifiers.sm3, DerNull.Instance);
            AlgorithmIdentifier digestEncryptAlgIdentifier = new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign, DerNull.Instance);
            return new SignerInfo(signInfoVersion, issuerAndSn, digestAlgIdentifier, null, digestEncryptAlgIdentifier, new DerOctetString(signData.ToAsn1Object()), null);
        }
    }
}