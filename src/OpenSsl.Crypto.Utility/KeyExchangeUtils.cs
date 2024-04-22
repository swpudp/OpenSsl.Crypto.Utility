using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 密钥协商工具
    /// </summary>
    public static class KeyExchangeUtils
    {
        public static DhParams CreateParameters(int size = 256)
        {
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(size, 0, new SecureRandom());
            DHParameters dHParameters = parametersGenerator.GenerateParameters();
            return new DhParams
            {
                G = dHParameters.G.ToString(),
                P = dHParameters.P.ToString()
            };
        }

        /// <summary>
        /// 生成密钥对
        /// </summary>
        public static CipherKeyPair CreateDhKeyPair(string p, string g)
        {
            DHParameters dHParameters = new DHParameters(new BigInteger(p), new BigInteger(g));
            return CreateDhKeyPairInternal(dHParameters);
        }

        private static CipherKeyPair CreateDhKeyPairInternal(DHParameters dHParameters)
        {
            IAsymmetricCipherKeyPairGenerator keyPairGenerator = GeneratorUtilities.GetKeyPairGenerator("DH");
            DHKeyGenerationParameters keyGenerationParameters = new DHKeyGenerationParameters(new SecureRandom(), dHParameters);
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            return CreateCipherKeyPair(keyPair);
        }

        /// <summary>
        /// 创建密钥
        /// </summary>
        /// <param name="alg">算法名称</param>
        /// <param name="pubHex">一方公钥</param>
        /// <param name="priHex">另一方私钥</param>
        /// <returns></returns>
        public static string CreateSecret(string alg, string pubHex, string priHex)
        {
            IBasicAgreement keyAgreement = AgreementUtilities.GetBasicAgreement(alg);
            AsymmetricKeyParameter pri = PrivateKeyFactory.CreateKey(HexUtils.ToByteArray(priHex));
            AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(HexUtils.ToByteArray(pubHex));

            keyAgreement.Init(pri);
            BigInteger key = keyAgreement.CalculateAgreement(pub);

            return HexUtils.ToHexString(key.ToByteArrayUnsigned());
        }

        /// <summary>
        /// 创建ecdh密钥对
        /// </summary>
        /// <returns></returns>

        public static CipherKeyPair CreateEcDhKeyPair()
        {
            X9ECParameters x9 = ECNamedCurveTable.GetByName("secp256k1");
            ECDomainParameters ecSpec = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);

            ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(ecSpec, new SecureRandom());
            IAsymmetricCipherKeyPairGenerator g = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            g.Init(keyGenerationParameters);

            AsymmetricCipherKeyPair keyPair = g.GenerateKeyPair();
            return CreateCipherKeyPair(keyPair);
        }

        private static CipherKeyPair CreateCipherKeyPair(AsymmetricCipherKeyPair keyPair)
        {
            string pri = HexUtils.ToHexString(PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded());
            string pub = HexUtils.ToHexString(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded());
            return new CipherKeyPair(pub, pri);
        }
    }

    public class DhParams
    {
        public string P { get; set; }
        public string G { get; set; }
    }
}
