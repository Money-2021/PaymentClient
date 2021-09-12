using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.secureidentity.api;

namespace Payment_Client
{
    class Helper
    {
        /// <summary>
        /// Find Node Host
        /// </summary>
        /// <param name="name">Node Secure Identity</param>
        /// <returns>Host URL</returns>
        public static string GetHostUrl(string name)
        {

            // Get secure Identity 
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);
            // Get host end point
            return EndPoint.get(id.host_sin);

        }
      
        
        public static bool IsNumeric(string value)
        {
            return value.All(char.IsNumber);
        }
     
    }
}
