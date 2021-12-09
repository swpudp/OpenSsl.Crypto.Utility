namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 加密密钥对
    /// </summary>
    public class CipherKeyPair
    {
        /// <summary>
        /// 公钥
        /// </summary>
        public string Public { get; set; }

        /// <summary>
        /// 私钥
        /// </summary>
        public string Private { get; set; }

        public CipherKeyPair() { }

        public CipherKeyPair(string publicKey, string privateKey)
        {
            Public = publicKey;
            Private = privateKey;
        }
    }
}
