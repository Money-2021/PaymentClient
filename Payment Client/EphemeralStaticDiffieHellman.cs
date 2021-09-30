﻿using System;
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
            CngKey orignKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            using (ECDiffieHellmanCng ephemeraKey = new ECDiffieHellmanCng(orignKey))
            {

                ephemeraKey.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash; // RFC 5753: dhSinglePass-stdDH-sha256kdf 
                ephemeraKey.HashAlgorithm = CngAlgorithm.Sha256;
                // Save EphemeralPUblicKey
                ephemeralPUblicKey = ephemeraKey.PublicKey.ToByteArray();
                CngKey recipientKey = CngKey.Import(staticPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] derivedKey = ephemeraKey.DeriveKeyMaterial(recipientKey);
                // InterLedger based ECIES uses AES-256, CBC mode, with PKCS7 Padding, with the all zero IV.
                byte[] bytesIV = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                using (Aes aes = new AesManaged())
                {
                    aes.Key = derivedKey;
                    aes.IV = bytesIV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7; // Old world default
                    return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
                }
              
            }  
        }
        
    }
}