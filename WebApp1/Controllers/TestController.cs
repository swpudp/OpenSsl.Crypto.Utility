using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenSsl.Crypto.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApp1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// 双方生成加密key
        /// </summary>
        /// <returns></returns>
        [HttpGet("key")]
        public string ExchangeKey(string pubKey)
        {
            return KeyManager.KeyExchange(pubKey);
        }

        /// <summary>
        /// 解密测试
        /// </summary>
        /// <returns></returns>
        [HttpGet("decrypt")]
        public bool Decrypt(string cipherText)
        {
            _logger.LogInformation($"decrypt：secertKey={KeyManager.SecertKey},cipherText={cipherText}");
            byte[] s = CryptoUtils.Sm4Decrypt(HexUtils.ToByteArray(KeyManager.SecertKey), HexUtils.ToByteArray(cipherText), CipherMode.CBC, CipherPadding.PKCS7);
            _logger.LogInformation("raw:" + Encoding.UTF8.GetString(s));
            return s.Length > 0;
        }
    }
}
