using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenSsl.Crypto.Utility.Internal;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestClass]
    public class RCTest
    {
        [TestMethod]
        public void RC4EncryptTest()
        {
            byte[] key = Encoding.UTF8.GetBytes("12345678abcdefgh");
            SecureRandom rd = new SecureRandom();
            for (int i = 1; i < 1000; i++)
            {
                byte[] raw = new byte[i];
                rd.NextBytes(raw);
                //byte[] raw = Encoding.UTF8.GetBytes("93E729D1269E40C990B5FC0088C91712");
                RCUtils.RC4(key, raw);
            }
        }
    }
}
