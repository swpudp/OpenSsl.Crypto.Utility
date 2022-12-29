using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSsl.Crypto.Utility.Internal
{
    internal static class SmExchangeKeyUtils
    {
        #region F-257

        private static readonly BigInteger SM2_ECC_A_257 = new BigInteger("00", 16);
        private static readonly BigInteger SM2_ECC_B_257 = new BigInteger("E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B", 16);
        private static readonly BigInteger SM2_ECC_N_257 = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D", 16);
        private static readonly BigInteger SM2_ECC_H_257 = BigInteger.ValueOf(4);
        private static readonly BigInteger SM2_ECC_GX_257 = new BigInteger("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD", 16);
        private static readonly BigInteger SM2_ECC_GY_257 = new BigInteger("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E", 16);
        private static readonly ECCurve curve_257 = new F2mCurve(257, 12, SM2_ECC_A_257, SM2_ECC_B_257, SM2_ECC_N_257, SM2_ECC_H_257);
        private static readonly ECPoint g_257 = curve_257.CreatePoint(SM2_ECC_GX_257, SM2_ECC_GY_257);
        private static readonly ECDomainParameters domainParams_257 = new ECDomainParameters(curve_257, g_257, SM2_ECC_N_257, SM2_ECC_H_257);

        #endregion

        #region F-256

        private static readonly BigInteger SM2_ECC_P_256 = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        private static readonly BigInteger SM2_ECC_A_256 = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        private static readonly BigInteger SM2_ECC_B_256 = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        private static readonly BigInteger SM2_ECC_N_256 = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        private static readonly BigInteger SM2_ECC_H_256 = BigInteger.One;
        private static readonly BigInteger SM2_ECC_GX_256 = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        private static readonly BigInteger SM2_ECC_GY_256 = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);
        private static readonly ECCurve curve_256 = new FpCurve(SM2_ECC_P_256, SM2_ECC_A_256, SM2_ECC_B_256, SM2_ECC_N_256, SM2_ECC_H_256);
        private static readonly ECPoint g_256 = curve_256.CreatePoint(SM2_ECC_GX_256, SM2_ECC_GY_256);
        private static readonly ECDomainParameters domainParams_256 = new ECDomainParameters(curve_256, g_256, SM2_ECC_N_256);

        #endregion

        public static AsymmetricCipherKeyPair CreateKeyPair(bool sm2p256v1)
        {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keyGenParams;
            if (sm2p256v1)
            {
                keyGenParams = new ECKeyGenerationParameters(domainParams_256, new Org.BouncyCastle.Security.SecureRandom());
            }
            else
            {
                keyGenParams = new ECKeyGenerationParameters(domainParams_257, new Org.BouncyCastle.Security.SecureRandom());
            }
            keyPairGenerator.Init(keyGenParams);
            return keyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// 解析私钥
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="sm2p256v1"></param>
        /// <returns></returns>
        public static ECPrivateKeyParameters ParseEcPrivateKey(byte[] bytes, bool sm2p256v1)
        {
            return new ECPrivateKeyParameters(new BigInteger(1, bytes), sm2p256v1 ? domainParams_256 : domainParams_257);
        }

        /// <summary>
        /// 解析公钥
        /// </summary>
        /// <param name="publicKeyBytes"></param>
        /// <returns></returns>
        public static ECPublicKeyParameters ParseEcPublicKey(byte[] publicKeyBytes, bool sm2p256v1)
        {
            var domainParams = sm2p256v1 ? domainParams_256 : domainParams_257;
            return new ECPublicKeyParameters(domainParams.Curve.DecodePoint(publicKeyBytes), domainParams);
        }
    }
}
