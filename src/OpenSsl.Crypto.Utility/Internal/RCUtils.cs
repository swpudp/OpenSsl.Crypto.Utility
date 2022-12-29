using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSsl.Crypto.Utility.Internal
{
    public static class RCUtils
    {
        public static void RC4(byte[] key, byte[] input)
        {
            var cipher = CipherUtilities.GetCipher("RC4");
            cipher.Init(true, new KeyParameter(key));
            byte[] output = new byte[input.Length];
            cipher.ProcessBytes(input, 0, input.Length, output, 0);
            string cipherText = HexUtils.ToHexString(output);
            Console.WriteLine("length {0} raw with length {1} chipherText:{2}", input.Length, output.Length, cipherText);
        }
    }
}
