namespace OpenSsl.Crypto.Utility
{
    /// <summary>
    /// ras签名算法，其中MD2、MD5、SHA1密钥长度1024，其他密钥长度2048
    /// </summary>
    public enum RsaSignerAlgorithm
    {
        MD2withRSA = 1,
        MD5withRSA = 2,
        SHA1withRSA = 3,
        //以下密钥长度均为2048
        SHA224withRSA = 4,
        SHA256withRSA = 5,
        SHA384withRSA = 6,
        SHA512withRSA = 7,
        RIPEMD128withRSA = 8,
        RIPEMD160withRSA = 9
    }
}
