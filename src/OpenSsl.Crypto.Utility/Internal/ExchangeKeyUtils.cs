using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace OpenSsl.Crypto.Utility.Internal
{
    /// <summary>
    /// 密钥交换工具
    /// </summary>
    public static class ExchangeKeyUtils
    {
        #region 国密密钥交换工具

        /// <summary>
        /// 创建sm密钥对
        /// </summary>
        /// <param name="sm2p256v1"></param>
        /// <returns></returns>
        public static AsymmetricCipherKeyPair CreateSmKeyPair(bool sm2p256v1)
        {
            return SmExchangeKeyUtils.CreateKeyPair(sm2p256v1);
        }

        /// <summary>
        /// 密钥交换
        /// </summary>
        /// <param name="staticPrivateKey">本方固定私钥</param>
        /// <param name="ephemeralPrivateKey">本方临时私钥</param>
        /// <param name="staticPublicKey">对方固定公钥</param>
        /// <param name="ephemeralPublicKey">对方临时公钥</param>
        /// <returns>密钥</returns>
        public static string SmKeyExchange(byte[] staticPrivateKey, byte[] ephemeralPrivateKey, byte[] staticPublicKey, byte[] ephemeralPublicKey)
        {
            SM2KeyExchange keyExchange = new SM2KeyExchange();
            //本方固定私钥和临时私钥
            ECPrivateKeyParameters aPriv = SmExchangeKeyUtils.ParseEcPrivateKey(staticPrivateKey, true);
            ECPrivateKeyParameters aePriv = SmExchangeKeyUtils.ParseEcPrivateKey(ephemeralPrivateKey, true);
            keyExchange.Init(new SM2KeyExchangePrivateParameters(true, aPriv, aePriv));
            //对方固定公钥和临时公钥
            ECPublicKeyParameters bPub = SmCertUtils.ParseEcPublicKey(staticPublicKey);
            ECPublicKeyParameters bePub = SmExchangeKeyUtils.ParseEcPublicKey(ephemeralPublicKey, true);
            byte[] key = keyExchange.CalculateKey(128, new ParametersWithID(new SM2KeyExchangePublicParameters(bPub, bePub), Strings.ToByteArray("BILL456@YAHOO.COM")));
            return HexUtils.ToHexString(key);
        }

        #endregion
    }
}
