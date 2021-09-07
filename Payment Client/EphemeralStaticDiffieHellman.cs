using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Payment_Client
{
    /// <summary>
    /// EphemeralStaticDiffieHellman Key Exchange 
    /// </summary>
    public class EphemeralStaticDiffieHellman
    {
       
        public static byte[] EncryptData( byte[] staticPublicKey, byte[] data, out byte[] ephemeralPUblicKey )
        {
            using (ECDiffieHellmanCng ephemeraKey = new ECDiffieHellmanCng())
            {

                ephemeraKey.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ephemeraKey.HashAlgorithm = CngAlgorithm.Sha256;
                // Save EphemeralPUblicKey
                ephemeralPUblicKey = ephemeraKey.PublicKey.ToByteArray();
                CngKey recipientKey = CngKey.Import(staticPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] keyAndIv = ephemeraKey.DeriveKeyMaterial(recipientKey);
                // Derive AES Key and IV
                byte[] key = new byte[16];
                Array.Copy(keyAndIv, 0, key, 0, 16);
                byte[] iv = new byte[16];
                Array.Copy(keyAndIv, 16, iv, 0, 16);
                // Preform Ecnryption
                Aes aes = new AesManaged();
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7; // Old world default
                return  aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

            }  
        }
        
    }
}