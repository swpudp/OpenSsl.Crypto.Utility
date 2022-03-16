using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 国密额外辅助工具
    /// </summary>
    public static class SmCertUtils
    {
        /// <summary>
        /// 生成密钥对（均为十六进制字符串）
        /// </summary>
        /// <param name="compressedPubKey">是否压缩公钥 默认压缩</param>
        /// <remarks>公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04</remarks>
        /// <returns>密钥对十六进制字符串</returns>
        public static CipherKeyPair GenerateKeyPair(bool compressedPubKey = true)
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");
            X9ECParameters x9EcParameters = GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
            ECDomainParameters eCDomainParameters = new ECDomainParameters(x9EcParameters);
            KeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(eCDomainParameters, random);
            IAsymmetricCipherKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair cipherKeyPair = generator.GenerateKeyPair();
            //提取公钥点
            ECPoint ecPoint = ((ECPublicKeyParameters)cipherKeyPair.Public).Q;
            //公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
            string publicKey = Hex.ToHexString(ecPoint.GetEncoded(compressedPubKey));
            BigInteger privateKey = ((ECPrivateKeyParameters)cipherKeyPair.Private).D;
            string priKey = Hex.ToHexString(privateKey.ToByteArray());
            return new CipherKeyPair(publicKey, priKey);
        }
    }
}