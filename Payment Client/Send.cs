using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.payment.api.Model;
using vm.data.library.blockchain.secureidentity.api;

namespace Payment_Client
{
    public class Send
    {
        /// <summary>
        /// Authorise a EDIFACT PAYORD
        /// </summary>
        /// <param name="name">User</param>
        /// <param name="msg">InterLedger Message</param>
        /// <returns>Payment Receipt</returns>
        public static Receipt AuthorisePayment(string name, vm.data.library.blockchain.cms.Msg.InterLedger msg)
        {
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);
            // Get host end point
            string BLOCKCHAINREG_URL = EndPoint.get(id.host_sin);

            // Setup HTTP Post
            String BLOCKCHAINREG_PLUGIN_INFO = "Block Chain Payment C# Library " + Settings.Default.BLOCKCHAINREG_API_VERSION + " on " + System.Environment.MachineName;
            HttpClient _httpClient = new(); 
            String _uri = BLOCKCHAINREG_URL + "Payment/PaymentOrder";
            _httpClient.BaseAddress = new Uri(_uri);
            try
            {
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("x-accept-version", Settings.Default.BLOCKCHAINREG_API_VERSION);
                _httpClient.DefaultRequestHeaders.Add("x-blockchain-plugin-info", BLOCKCHAINREG_PLUGIN_INFO);
                // JwtSecurityToken payment authorization
                _httpClient.DefaultRequestHeaders.Add("x-authorization",id.token);
                _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));


                // Generate signature
                byte[] signature = Device.SignData(name, Encoding.UTF8.GetBytes(id.sin));
                // Check
                bool bResult = Device.VerifyData(id.label, Encoding.UTF8.GetBytes(id.sin), signature);
                _httpClient.DefaultRequestHeaders.Add("x-signature", Convert.ToBase64String(signature));
                // Add requesting Secure Identity
                _httpClient.DefaultRequestHeaders.Add("x-identity", id.sin);
                // Add JWT Token from device registration
                if (!String.IsNullOrEmpty(id.token))
                    _httpClient.DefaultRequestHeaders.Add("x-authorization", id.token);
                // Post Content
                HttpResponseMessage response = _httpClient.PostAsJsonAsync(_uri, msg).Result;
                byte[] content = response.Content.ReadAsByteArrayAsync().Result;
                string sjson = System.Text.Encoding.ASCII.GetString(content);
                // Decode JSON 
                JsonMediaTypeFormatter mf = new ();
                MemoryStream ms = new (content);
                Task<object> d = mf.ReadFromStreamAsync(typeof(Receipt), ms, null, null);
                Receipt receiptData = (Receipt)d.Result;

                return receiptData;
            }
            catch (Exception ex)
            {
                throw new Exception("Error: " + ex.ToString());
            }
        }


    }
}
