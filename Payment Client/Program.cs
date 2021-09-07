using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.payment.api.Model;
using vm.data.library.blockchain.secureidentity.api;

namespace Payment_Client
{
    /// <summary>
    /// All Rights Reserved Villagemall Pty Ltd. 
    /// Distributed under the attached MIT License.
    /// </summary>
    class Program
    {
       
        static void Main()
        {
            // HSM Secure Identity to bind this device to...
            string AliceName = "Alice";
            string AliceSin = String.Empty ;
            // Test Token, replace with your node issued JwtSecurityToken
            string sJwtSecurityToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJUeE5vIjoiNmQ4YzkzNGEtNTg3Ni00OWVjLWE3YTktNmEzZDMyNGI0NDg4IiwibmFtZWlkIjoiMDEwMTE0MkVDM0UxQkU3REFCNTBFQTJGRUYyODIzRkNDRDc4QzU2OEVEOTExNCIsIm5iZiI6MTYzMDk2MzgzNywiZXhwIjoxNjMxNTY4NjM1LCJpYXQiOjE2MzA5NjM4MzcsImlzcyI6IjAxMDExNEUyMjU0RkNBODM1QjUwODU2MDFDQ0UyNDc5NENFODg0NDM0ODJFN0YiLCJhdWQiOiJEZXZpY2UgUmVnaXN0cmF0aW9uIn0.6LQWwCssoaDBOY5AuGswePFiMrbd2o6Appf535Av5PU";
            // Test Payee, replace with actual payee Secure Identity
            string JohnSin = "0101148159A9B51BAFD8193139C8E7FDBECC9E2BC1E56F";

            // Staging Steps
            // Decode JWToken
            var jwtToken = new JwtSecurityToken(sJwtSecurityToken);
            string NodeSin = jwtToken.Issuer.ToString();
            IEnumerable<Claim> claims = jwtToken.Claims;
            // Check JwtSecurityToken expire for validity..
            DateTime expire = jwtToken.ValidTo;
            // Extract registration data, with the claims
            foreach (Claim claim in claims )
            {
                switch(claim.Type)
                {
                    case "TxNo":
                        break;
                    case "nameid":
                        AliceSin = claim.Value;
                        break;
                }

            }
           

            // Step 1: Code Payment client, Registration
            DeviceSecureIdentities ids = new DeviceSecureIdentities(Settings.Default.SECUREIDENTIES);
            if (ids.identities.Count == 0)
            {
                if (CngKey.Exists(AliceName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                {
                    CngKey key = CngKey.Open(AliceName);
                    key.Delete();
                }
                // Initialise Device Keys
                Device.GenECDSAKeys(AliceName, AliceSin, NodeSin);
                Device.GenECDHKeys(AliceName, AliceSin, NodeSin);
                
            }
            // Register Device
            String registrationToken = "";
            String recoveryToken = Register.RegisterDevice(AliceName, NodeSin, AliceSin, null, sJwtSecurityToken);
            
            // Step 2: Code Payment client, Payment authorisation 
            // Debit Party
            DeviceSecureIdentity id = ids.getLastByLable(AliceName, SinNodeType.Payment);
            byte[] assetId = Device.AssetId("ISO4217|EUR"); // Select EUR Payment

            // Setup Inter-ledger Message
            vm.data.library.blockchain.cms.Msg.InterLedger req = new vm.data.library.blockchain.cms.Msg.InterLedger();
            // Setup Header info before call
            req.header = new vm.data.library.blockchain.cms.Msg.InterLedger.Header();
            req.header.sourceNodeSecureIdentity = id.host_sin; 
            req.header.sourceSecureIdentity = id.sin;
            req.header.destNodeSecureIdentity = id.host_sin; // same for test
            req.header.destSecureIdentity = JohnSin;
            req.header.TxNo = Guid.NewGuid(); // Will become Public Block Chain Ledger->BlockNo
            // Build PAYORD InterLedger Message
            Interledger.BuildPayOrd(AliceName, req, assetId, 100, "Test Payment");
            // Process P2P Payment
            Receipt receipt = Send.AuthorisePayment(AliceName, req); 

        }
    }
}
