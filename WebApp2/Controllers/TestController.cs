using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenSsl.Crypto.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace WebApp2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ILogger<TestController> _logger;
        private readonly IHttpClientFactory _clientFactory;
        public TestController(ILogger<TestController> logger, IHttpClientFactory clientFactory)
        {
            _logger = logger;
            _clientFactory = clientFactory;
        }

        /// <summary>
        /// 发生数据测试
        /// </summary>
        /// <returns></returns>
        [HttpGet("transport")]
        public async Task<bool> Transport()
        {
            await GetSecretKey();
            var raw = Guid.NewGuid().ToString("N");
            byte[] cipher = CryptoUtils.Sm4Encrypt(HexUtils.ToByteArray(KeyManager.SecertKey), Encoding.UTF8.GetBytes(raw), CipherMode.CBC, CipherPadding.PKCS7);
            string cipherText = HexUtils.ToHexString(cipher);
            _logger.LogInformation($"encrypt raw ={raw},secertKey={KeyManager.SecertKey},cipherText={cipherText}");
            using (var client = _clientFactory.CreateClient())
            {
                var result = await client.GetAsync("http://localhost:5001/test/decrypt?cipherText=" + cipherText);
                result.EnsureSuccessStatusCode();
                string isSuccessText = await result.Content.ReadAsStringAsync();
                return bool.TryParse(isSuccessText, out bool isSuccess) && isSuccess;
            }
        }

        private async Task GetSecretKey()
        {
            if (!string.IsNullOrEmpty(KeyManager.SecertKey))
            {
                return;
            }
            var keyPair = SmCertUtils.GenerateKeyPair(false);
            using (var client = _clientFactory.CreateClient())
            {
                var result = await client.GetAsync("http://localhost:5001/test/key?pubKey=" + keyPair.Public);
                result.EnsureSuccessStatusCode();
                string pubKey = await result.Content.ReadAsStringAsync();
                KeyManager.KeyExchange(pubKey);
            }
        }
    }
}
