using OpenSsl.Crypto.Utility;
using OpenSsl.Crypto.Utility.Internal;

namespace WebApp1.Controllers
{
    public static class KeyManager
    {
        public const string staticPrivateKey = "00DC6B7BDC78876974426F8B74528D49414C7A4E3307075BFF06700A3F2C2C8E9A";
        public const string staticPublicKey = "043588FE06493DA8F81F448AF6496941F5421A780EC25B25E45C9F4CF6B82CFAB4028861E44E8F532A02F1280E46886725EA2F1DF122B752090F5711907E90C593";
        //系统2的公钥
        public const string app2PublicKey = "04A509B3826350B5DFBF9DD50484DC05E5FD8117EFF3A25ED86EB896681EB509B984B0FC795BB1903446BA2F0DE883B6B3FFC0839D6693E0BD89D5D5D89692233F";
        private static string secertKey;
        public static string SecertKey => secertKey;
        public static string KeyExchange(string pubKey)
        {
            var keyPair = ExchangeKeyUtils.CreateSmKeyPair(true);
            secertKey = ExchangeKeyUtils.SmKeyExchange(HexUtils.ToByteArray(staticPrivateKey), SmCertUtils.GetPrivateKey(keyPair.Private), HexUtils.ToByteArray(app2PublicKey), HexUtils.ToByteArray(pubKey));
            return HexUtils.ToHexString(SmCertUtils.GetPublicKey(keyPair.Public));
        }
    }
}
