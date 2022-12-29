using OpenSsl.Crypto.Utility;
using OpenSsl.Crypto.Utility.Internal;

namespace WebApp2.Controllers
{
    public static class KeyManager
    {
        public const string staticPrivateKey = "00E02A5F40C994B9D0BE8E44669FE0A3245E189A72B5DD0B118D02CC24CDB4AB02";
        public const string staticPublicKey = "04A509B3826350B5DFBF9DD50484DC05E5FD8117EFF3A25ED86EB896681EB509B984B0FC795BB1903446BA2F0DE883B6B3FFC0839D6693E0BD89D5D5D89692233F";
        //系统1的公钥
        public const string appPublicKey = "043588FE06493DA8F81F448AF6496941F5421A780EC25B25E45C9F4CF6B82CFAB4028861E44E8F532A02F1280E46886725EA2F1DF122B752090F5711907E90C593";
        private static string secretKey;
        public static string SecertKey => secretKey;
        public static void KeyExchange(string pubKey)
        {
            var keyPair = ExchangeKeyUtils.CreateSmKeyPair(true);
            secretKey = ExchangeKeyUtils.SmKeyExchange(HexUtils.ToByteArray(staticPrivateKey), SmCertUtils.GetPrivateKey(keyPair.Private), HexUtils.ToByteArray(appPublicKey), HexUtils.ToByteArray(pubKey));
        }
    }
}
