namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// 填充方式
    /// </summary>
    public enum CipherPadding
    {
        NONE,
        RAW,
        ISO10126,
        ISO7816d4,
        ISO97961,
        OAEP,
        OAEPWITHMD5ANDMGF1,
        OAEPWITHSHA1ANDMGF1,
        OAEPWITHSHA224ANDMGF1,
        OAEPWITHSHA256ANDMGF1,
        OAEPWITHSHA256ANDMGF1WITHSHA256,
        OAEPWITHSHA256ANDMGF1WITHSHA1,
        OAEPWITHSHA384ANDMGF1,
        OAEPWITHSHA512ANDMGF1,
        PKCS1,
        PKCS5,
        PKCS7,
        TBC,
        WITHCTS,
        X923,
        ZEROBYTE,
    };
}
