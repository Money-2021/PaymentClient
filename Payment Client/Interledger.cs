using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Formatting;
using System.Text;
using System.Threading.Tasks;
using vm.data.library.blockchain.api.device.Model;
using vm.data.library.blockchain.cms.Model;
using vm.data.library.blockchain.cms.Msg;
using vm.data.library.blockchain.secureidentity.api;

namespace Payment_Client
{
    public class Interledger
    {
        /// <summary>
        /// Inter Ledger Data Unit-PAYORD
        /// </summary>
        /// <param name="name">KeyId</param>
        /// <param name="creditSin">Payee</param>
        /// <param name="creditNodeSin">Payee Node</param>
        /// <param name="txNo">Trasnaction Number</param>
        /// <param name="assetId">Currency</param>
        /// <param name="amount">Amount</param>
        /// <param name="description">Text Desciption</param>
        /// <returns>InterLedger Data Unit</returns>
        public static InterLedger BuildPayOrd(string name, InterLedger req, byte[] assetId, decimal amount, string description)
        {
            DeviceSecureIdentities ids = new DeviceSecureIdentities(Settings.Default.SECUREIDENTIES);
            DeviceSecureIdentity id = ids.getLastByLable(name, SinNodeType.Payment);

            // Add EDIFACT Payment Data
            vm.data.library.blockchain.payment.api.Model.PAYORD pdata = new vm.data.library.blockchain.payment.api.Model.PAYORD();
            pdata.version = 1;
            // Fill to be signed elements from header
            pdata.creditSin = req.header.destSecureIdentity; // Credit SecureIdentity
            pdata.creditNodeSin = req.header.destNodeSecureIdentity;
            pdata.debitSin = req.header.sourceSecureIdentity; // Debit SecureIdentity
            pdata.debitNodeSin = req.header.sourceSecureIdentity; ;
            pdata.TxNo = req.header.TxNo;  // Will become Alice/John Public Block Chain Ledger->BlockNo 
            pdata.trandate = DateTime.UtcNow;
            // Fill from call parameters
            pdata.amount = amount;
            pdata.debitAssetId = assetId;
            pdata.creditAssetId = assetId; 
            pdata.description = description;
     
            // Device signature
            SignerInfo dsign = new SignerInfo();
            dsign.digestAlgorithm = vm.data.library.blockchain.cms.Model.Oid.SHA_256;
            dsign.signatureAlgorithm = vm.data.library.blockchain.cms.Model.Oid.ECDSA_256;
            vm.data.library.blockchain.cms.Model.Attribute att = new vm.data.library.blockchain.cms.Model.Attribute();
            att.attributeType = vm.data.library.blockchain.cms.Model.Oid.PAYORD_DATA;
            // Searialise to Sign
            JsonMediaTypeFormatter mf = new JsonMediaTypeFormatter();
            MemoryStream ms = new MemoryStream();
            mf.WriteToStreamAsync(pdata.GetType(), pdata, ms, null, null);
            ms.Seek(0, SeekOrigin.Begin);
            // Save Hash
            att.attributeValue = Device.ComputeHash(ms.ToArray());
            // Sign attribute
            dsign.signatureValue = Device.SignHashData(id.label, att.attributeValue);
            // Verify 
            bool bResult = Device.VerifyData(id.label, att.attributeValue, dsign.signatureValue);
            // Add to SignerInfo
            dsign.signedAttributes = new List<vm.data.library.blockchain.cms.Model.Attribute>();
            dsign.signedAttributes.Add(att);
            dsign.signerIdentifier = new SignerIdentifier();
            dsign.signerIdentifier.secureIdentity = id.sin; //req.header.sourceSecureIdentity;
            dsign.signerIdentifier.publicKeyBlob = id.ecdsa_PublicKeyBlob;
            // Add Siganture to PAYORD
            pdata.signatureCollection.signatures.Add(dsign);

            // Serialise complete PAYORD
            ms = new MemoryStream();
            mf.WriteToStreamAsync(pdata.GetType(), pdata, ms, null, null);
            ms.Seek(0, SeekOrigin.Begin);

            // Encrypt JSON PAYORD data
            byte[] hostPublicKey = id.host_sin_ecdh_PublicKeyBlob; // Encrypt to NodeSin ECDH public key
            byte[] ephemerialEcdhPublicKey = null;
            byte[] encPayData = EphemeralStaticDiffieHellman.EncryptData(ms.ToArray(), hostPublicKey, out ephemerialEcdhPublicKey);
           
            // Wrap PAYORD within CMS ContentInfo
            req.data = new vm.data.library.blockchain.cms.Model.ContentInfo();
            req.data.contentType = vm.data.library.blockchain.cms.Model.Oid.CONTENTTYPE_ENVELOPED_DATA;
            req.data.contentMimeType = "application/json";

            // Fill CMS EnvelopedData
            vm.data.library.blockchain.cms.Model.EnvelopedData eData = vm.data.library.blockchain.cms.Msg.EnvelopedCms.create(req.header.sourceSecureIdentity, req.header.sourceNodeSecureIdentity, ephemerialEcdhPublicKey, vm.data.library.blockchain.cms.Model.Oid.PAYORD_DATA, encPayData.ToArray());

            // Serialize EnvelopedData
            ms = new MemoryStream();
            mf.WriteToStreamAsync(eData.GetType(), eData, ms, null, null);
            ms.Seek(0, SeekOrigin.Begin);

            // Add to Request Msg->ContentInfo
            req.data.content = ms.ToArray();
          
            return req;
        }
    }
}
