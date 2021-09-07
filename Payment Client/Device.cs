using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.secureidentity.api;


namespace Payment_Client
{
    public class Device
    {
        /// <summary>
        /// Retrieve ECDH key associated with Node Secure Identifier, returned from initial registration response.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="host_sin">Host Secure Identifier</param>
        /// <returns></returns>
        public static byte[] GetHostECDHKey(string name, string host_sin)
        {
            DeviceSecureIdentities ids = new(Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.get(name, host_sin, SinNodeType.Payment);
            return id.host_sin_ecdh_PublicKeyBlob;
        }

        #region KeyGeneration
        /// <summary>
        /// Generate and Store ECDSA Device Identity Key Pairs
        /// </summary>
        /// <param name="name">Local Label </param>
        /// <param name="sin">Secure Identity</param>
        /// <param name="host_sin">Host Secure Identity</param>
        /// <returns></returns>
        public static string GenECDSAKeys(string name, string entity_sin, string host_sin)
        {
            string sin = Provider.GenECDSAKeys(name);
            DeviceSecureIdentities ids = new(Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = null;
            // check
            List<DeviceSecureIdentity> a = ids.identities.Where(x => x.label == name).ToList();

            if (ids.list(name, host_sin).Any())
            {
                id = ids.list(name, host_sin).FirstOrDefault();
                // Update Existing
                id.ecdsa_PublicKeyBlob = Provider.GetECDSAPubKey(name);
                id.sin = id.getSecureIdentity(sinType.ephemeral); // mark these as ephemeral

            }
            else
            {

                // Add New
                id = new DeviceSecureIdentity
                {
                    label = name,
                    entity_sin = entity_sin, // Node HSM Secure Identity
                    host_sin = host_sin,     // Node Secure Identity
                    host_type = SinNodeType.Payment, // Select Payment Rail

                    // ECDSA
                    ecdsa_PublicKeyBlob = Provider.GetECDSAPubKey(name)
                };
                id.sin = id.getSecureIdentity(sinType.ephemeral); // make these ephemeral
                ids.identities.Add(id);

            }
            // Save 
            Settings.Default.SECUREIDENTIES = ids.asJason();
            Settings.Default.Save();
            return id.sin;
        }
        /// <summary>
        /// Generate and Store ECDH Key Pairs
        /// </summary>
        public static void GenECDHKeys(string name, string sin, string host_sin)
        {
            Provider.GenECDHKeys(name);
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id;
            // check
            if (ids.list(name, host_sin).Any())
            {
                id = ids.list(name, host_sin).FirstOrDefault();
                // Update Existing
                id.ecdh_PublicKeyBlob = Provider.GetECDHPubKey(name);
            }
            else
            {
                // Add New
                id = new DeviceSecureIdentity
                {
                    label = name,
                    host_type = SinNodeType.Payment,
                    entity_sin = sin,
                    host_sin = host_sin,

                    // ECDH
                    ecdh_PublicKeyBlob = Provider.GetECDHPubKey(name)
                };
                ids.identities.Add(id);

            }
            // Save 
            Settings.Default.SECUREIDENTIES = ids.asJason();
            Settings.Default.Save();

        }
        #endregion
        /// <summary>
        /// Sign the SHA256 hash of the data
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] SignHashData(string name, byte[] data)
        {
            using SHA256 dSHA256 = SHA256.Create();
            byte[] hashBytes = dSHA256.ComputeHash(data);
            return SignHash(name, hashBytes);


        }
        public static byte[] ComputeHash(byte[] data)
        {
            using SHA256 dSHA256 = SHA256.Create();
            byte[] hashBytes = dSHA256.ComputeHash(data);
            return hashBytes;


        }
        /// <summary>
        /// Sign the SHA256 Hash
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hash"></param>
        /// <returns></returns>
        public static byte[] SignHash(string name, byte[] hash)
        {

            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);

            byte[] signature = Provider.SignHash(hash, id.label);
            bool bResult = Provider.VerifyHash(hash, signature, name);
            if (bResult == false)
                throw new Exception("Error: Signature Verify Failed");
            return signature;
        }
        /// <summary>
        /// Sign Data, using provider key store
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] SignData(string name, byte[] data)
        {
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);
            byte[] signature = Provider.SignData(data, id.label);
            bool bResult = Provider.VerifyData(data, signature, name);
            if (bResult == false)
                throw new Exception("Error: Signature Verify Failed");
            return signature;

        }
        /// <summary>
        /// Verify Hash Signature
        /// </summary>
        /// <param name="name"></param>
        /// <param name="hash"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public static bool VerifyHash(string name, byte[] hash, byte[] signature)
        {
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);
            return Provider.VerifyHash(hash, signature, id.label);
          
        }
        /// <summary>
        /// Verify SHA256 of data, signature
        /// </summary>
        /// <param name="name"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public static bool VerifyData(string name, byte[] data, byte[] signature)
        {
            DeviceSecureIdentities ids = new (Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);
            return Provider.VerifyData(data, signature, id.label);
           
        }
        /// <summary>
        /// Retrieve ECDSA Public Key
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static byte[] GetECDSAPubKey(string keyName)
        {
            CngProvider keyProvider = new CngProvider("Microsoft Platform Crypto Provider");
            var k = CngKey.Open(keyName, keyProvider);
            return k.Export(CngKeyBlobFormat.EccPublicBlob);
        }
        /// <summary>
        /// REturn Device Secure Identity
        /// </summary>
        /// <param name="name"></param>
        /// <returns>SIN</returns>
        public static string GetDeviceSecureIdenty(string keyName)
        {

            DeviceSecureIdentity d = new DeviceSecureIdentity();
            d.ecdsa_PublicKeyBlob = GetECDSAPubKey(keyName);
            return d.getSecureIdentity(sinType.ephemeral);
        }
        /// <summary>
        /// Globally Unique Asset Identifier 
        /// </summary>
        /// <param name="sdata">Asset String</param>
        /// <returns>Asset Identifier</returns>
        public static byte[] AssetId(string sdata)
        {
            byte[] data = Encoding.UTF8.GetBytes(sdata);
            using SHA256 dSHA256 = SHA256.Create();
            using RIPEMD160 dRIPEMD160 = RIPEMD160.Create();
            // Asset Identifdiers are a double Hash
            byte[] hashBytes = dRIPEMD160.ComputeHash(dSHA256.ComputeHash(data));
            return hashBytes;
        }
        /// <summary>
        /// Generate Key Identifier
        /// </summary>
        /// <param name="PublicKey"></param>
        /// <returns>Key Identifier</returns>
        public static string KeyId(byte[] PublicKey)
        {
            using RIPEMD160 hash = RIPEMD160.Create();
            return Convert.ToBase64String(hash.ComputeHash(PublicKey));

        }

    }
}
