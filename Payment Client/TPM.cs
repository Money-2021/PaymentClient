using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.secureidentity.api;

namespace Payment_Client
{
    /// <summary>
    /// This is a public domain, non hardware based software cryptographic provider.
    /// A Hardware based TPM based provider is proprietry, and avaiable from your Payment Node Operator.
    /// This client has been designed to support the generic risks assocaited with payments upto $1,000 of value.
    /// </summary>
    class Provider
    {
        private static readonly CngProvider microsoftSoftwareKeyStorageProvider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
      /// <summary>
      /// Generate ECDSA key pairs within provider store
      /// </summary>
      /// <param name="keyName"></param>
      /// <returns>Secure Identity</returns>
        public static string GenECDSAKeys(string keyName)
        {

            const bool MachineKey = false;
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                var keyParams = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                    KeyCreationOptions = (MachineKey) ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
                    Provider = microsoftSoftwareKeyStorageProvider
                };

                CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, keyParams);
                byte[] publicKeyBytes = key.Export(System.Security.Cryptography.CngKeyBlobFormat.EccPublicBlob);
                // Return Secure Identity 
                return  SecureIdentity.Create(publicKeyBytes, vm.data.library.blockchain.secureidentity.api.sinType.ephemeral);
           }
            else
            {
                throw new CryptographicException($"The key with the name '{keyName}' already exists!");
            }
        }
        /// <summary>
        /// Export ECDSA public key from provider key store
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns>Public Key</returns>
        public static byte[] GetECDSAPubKey(string keyName)
        {
            if (CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                return  key.Export(System.Security.Cryptography.CngKeyBlobFormat.EccPublicBlob);
            }
            else
                throw new CryptographicException($"The key with the name '{keyName}' does not exist!");

        }
        /// <summary>
        /// Generate ECDH exchange key pairs, within provider store
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns>Public Key</returns>
        public static byte[]  GenECDHKeys(string keyName)
        {

            keyName = GetECDHKeyName(keyName); ;
            const bool MachineKey = false;
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                var keyParams = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                    KeyCreationOptions = (MachineKey) ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
                    Provider = microsoftSoftwareKeyStorageProvider
                };

                CngKey key =  CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, keyParams);
                return key.Export(System.Security.Cryptography.CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                throw new CryptographicException($"The key with the name '{keyName}' exists!");
            }
        }
        /// <summary>
        /// Export ECDH public key from provider key store
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static byte[] GetECDHPubKey(string keyName)
        {
            keyName = GetECDHKeyName(keyName);
            if (CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                return key.Export(System.Security.Cryptography.CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                throw new CryptographicException($"The key with the name '{keyName}' does not exists!");
            }
        }
        public static string GetECDHKeyName(string keyName)
        {
            return keyName + "ECDH";
        }
        /// <summary>
        /// Sign hashBytes, with ECDSA key from provider key store
        /// </summary>
        /// <param name="hashBytes">SHA256 Hash</param>
        /// <param name="keyName"></param>
        /// <returns>Signature</returns>
        public static byte[] SignHash(byte[] hashBytes, string keyName)
        {
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                using DSACng signer = new (key);
                return signer.SignData(hashBytes, HashAlgorithmName.SHA256);

            }
            else
                throw new CryptographicException($"The key with the name '{keyName}' does not exists!");
        }
        /// <summary>
        /// Verify hashBytes using public key from provider key store
        /// </summary>
        /// <param name="hashBytes">SHA256 Hash</param>
        /// <param name="signature">Siganture</param>
        /// <param name="keyName"></param>
        /// <returns>boolean result</returns>
        public static bool VerifyHash(byte[] hashBytes, byte[] signature, string keyName)
        {
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                using DSACng signer = new (key);
                return signer.VerifySignature(hashBytes, signature);
            }
            else
                throw new CryptographicException($"The key with the name '{keyName}' does not exists!");
        }
        /// <summary>
        /// Calaculate SHA256 hash, then ECDSA Signature using private key from provider key store
        /// </summary>
        /// <param name="data">Data to Sign</param>
        /// <param name="keyName"></param>
        /// <returns>Signature</returns>
        public static byte[] SignData(byte[] data, string keyName)
        {
            byte[] hashBytes;
            using (SHA256 dSHA256 = SHA256.Create())
            {
                hashBytes = dSHA256.ComputeHash(data);
            }
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                using DSACng signer = new (key);
                return signer.SignData(hashBytes, HashAlgorithmName.SHA256);
            }
            else
                throw new CryptographicException($"The key with the name '{keyName}' does not exists!");
        }
        /// <summary>
        /// Calaculate SHA256 Hash, then verify signature; using public key from provider key store
        /// </summary>
        /// <param name="data">Data to Verify</param>
        /// <param name="signature"></param>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static bool VerifyData(byte[] data, byte[] signature, string keyName)
        {
            byte[] hashBytes;
            using (SHA256 dSHA256 = SHA256.Create())
            {
                hashBytes = dSHA256.ComputeHash(data);
            }
            if (!CngKey.Exists(keyName, microsoftSoftwareKeyStorageProvider))
            {
                CngKey key = CngKey.Open(keyName);
                using DSACng signer = new (key);
                return signer.VerifySignature(hashBytes, signature);
            }
            else
                throw new CryptographicException($"The key with the name '{keyName}' does not exists!");
        }
    }

}
