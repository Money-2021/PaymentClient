
    public class DeviceToken
    {
        public class RecoveryResponse
        {
            public RecoveryResponse()
            {
            }
            public RecoveryResponse(bool protect = false)
            {
                isProtected = protect;
            }
            public byte[] share { get; set; }
            public string jwToken { get; set; }
            public bool? isProtected { get; set; } //  encrypted setupcode
        }
        public class DeviceStore
        {
            public string SecureIdentity { get; set; }      // HSM Secure Identity
            public string DeviceSin { get; set; }           // Device Secure Identity
            public string JwToken { get; set; }             // Device JWToken
            public long Counter { get; set; }
            public byte[] Share { get; set; }
            public bool? isProtected { get; set; } //  encrypted setupcode

            public DeviceStore()
            {
               
            }
            public DeviceStore(bool protect = false)
            {
                isProtected = protect;
            }
      
        }
        public static string SignHash(string tokenPath, byte[] hashBytes)
        {
            DeviceStore store = GetDeviceToken(tokenPath);
            // Extract Function endpoint from Token
            var securityToken = new JwtSecurityToken(store.JwToken);
            Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
            // Obtain Function JwToken
            HttpClient _httpClient = new HttpClient();
            // Build funtion endpoint Uri
            string _relativeUrl = "User/SignHash";
            Uri _uri = new Uri(_baseUri, _relativeUrl);
            _httpClient.BaseAddress = _baseUri;
            _httpClient.DefaultRequestHeaders.Add("x-token", store.JwToken);
            // Add User Counter
            _httpClient.DefaultRequestHeaders.Add("x-counter", store.Counter.ToString());
            _httpClient.DefaultRequestHeaders.Add("x-hash", Convert.ToBase64String(hashBytes));
            // Add Jws 
            string ssign = HmacProvider.SignHash(store.Share, hashBytes);
            _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
            string functionToken = string.Empty;
            HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
            if (response.IsSuccessStatusCode)
            {
                functionToken = response.Content.ReadAsStringAsync().Result;
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                // Sync issue detected -> resync
                RecoveryResponse r = TokenRefresh(store.Share, store.JwToken);
                store.JwToken = r.jwToken;
                store.Share = r.share; // Mandatory refresh
                store.Counter = 1;
                store.isProtected = false; // unprotected from refresh
                // Save 
                SaveDevice(tokenPath, store);

            }
            else
            {
                string sError = response.Content.ReadAsStringAsync().Result;
                throw new Exception(sError);
            }
            // Increment
            IncrementCounter(tokenPath);
            return functionToken;
        }
        public static void IncrementCounter(string userTokenPath)
        {
            // Serialise
            JsonSerializerOptions jso = new JsonSerializerOptions();
            jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
            string sToken = System.IO.File.ReadAllText(userTokenPath);
            DeviceStore store = System.Text.Json.JsonSerializer.Deserialize<DeviceStore>(sToken, jso);
            store.Counter = store.Counter + 1;
            // Save
            string json = System.Text.Json.JsonSerializer.Serialize<DeviceStore>(store, jso);
            System.IO.File.WriteAllText(userTokenPath, json);

        }
        public static DeviceStore GetDeviceToken(string storePath)
        {
            string sToken = System.IO.File.ReadAllText(storePath);
            DeviceStore store = JsonSerializer.Deserialize<DeviceStore>(sToken);
            // Check protected
            if (store.isProtected.HasValue == false || store.isProtected == false)
            {

                // Always protect
                store.isProtected = true;
                byte[] encCode = Protect(store.Share);
                // Check 
                byte[] pCode = UnProtect(encCode);
                if (ByteArraysEqual(pCode, store.Share) == false)
                    throw new Exception("Share different");
                store.Share = encCode;
                // Save with encypted setupcode
                string json = System.Text.Json.JsonSerializer.Serialize<DeviceStore>(store);
                System.IO.File.WriteAllText(storePath, json);
                // Return plaintext
                store.Share = pCode;

            }
            else if (store.isProtected == true)
            {
                byte[] pCode = UnProtect(store.Share);
                store.Share = pCode;                
            }
            // Check expire exp
            var securityToken = new JwtSecurityToken(store.JwToken);
            var issuedAt = securityToken.IssuedAt;
            var validTo = securityToken.ValidTo;
            // Check refresh window 2 days before expired
            if (DateTime.UtcNow >= validTo.AddDays(-2))
            {
                RecoveryResponse r = TokenRefresh(store.Share, store.JwToken);
                securityToken = new JwtSecurityToken(r.jwToken);
                issuedAt = securityToken.IssuedAt;
                validTo = securityToken.ValidTo;

                // Update UserToken
                store.JwToken = r.jwToken;
                store.Share = r.share; // Mandatory refresh
                store.isProtected = false; // unprotected from refresh
                store.Counter = 1;
                // Save 
                SaveDevice(storePath, store);
            }
            return store;
        }
        private static RecoveryResponse TokenRefresh(byte[] share, string jwToken)
        {
            // Extract Function endpoint from User Token
            var securityToken = new JwtSecurityToken(jwToken);
            var claim = securityToken.Claims.FirstOrDefault(x => x.Type == "SecureIdentity");
            string _secureIdentity = claim.Value;
            claim = securityToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti);
            string _jti = claim.Value;

            Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
            // Obtain Function JwToken
            HttpClient _httpClient = new HttpClient();
            // Build funtion endpoint Uri
            string _relativeUrl = "Device/TokenRefresh";
            Uri _uri = new Uri(_baseUri, _relativeUrl);
            _httpClient.BaseAddress = _baseUri;
            // Add User Jwtoken
            _httpClient.DefaultRequestHeaders.Add("x-token", jwToken);
            // Add Device Signature 
            byte[] dataBytes = Encoding.UTF8.GetBytes(_secureIdentity + _jti);
            // Device Signs Payment
            byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(_secureIdentity + _jti));
            string ssign = HmacProvider.SignHash(share, hashBytes);
            _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
            // Get response
            HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
            if (response.IsSuccessStatusCode)
            {
                // pass
                string json = response.Content.ReadAsStringAsync().Result;
                // New Rec
                return JsonSerializer.Deserialize<RecoveryResponse>(json);
            }
            else
            {
                // fail
                string error = response.Content.ReadAsStringAsync().Result;
                throw new Exception(error);
            }
        }
        public static void SaveDevice(string userTokenPath, DeviceStore store)
        {
            // Encrypt setupcode
            // Check protected
            if (store.isProtected.HasValue == false || store.isProtected == false)
            {
                // setupcode in plaintext. so protect
                store.Share = Protect(store.Share);
                store.isProtected = true;
            }
            // Serialise
            JsonSerializerOptions jso = new JsonSerializerOptions();
            jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
            string json = JsonSerializer.Serialize<DeviceStore>(store, jso);
            System.IO.File.WriteAllText(userTokenPath, json);

        }
        private static byte[] Protect(byte[] share)
        {
            byte[] encBytes = ProtectedData.Protect(share, null, DataProtectionScope.CurrentUser);
            return encBytes;
        }
        private static byte[] UnProtect(byte[] share)
        {
             byte[] pBytes = ProtectedData.Unprotect(share, null, DataProtectionScope.CurrentUser);
            return pBytes;
        }
        static bool ByteArraysEqual(byte[] a1, byte[] a2)
        {
            return StructuralComparisons.StructuralEqualityComparer.Equals(a1, a2);
        }
        public class HmacProvider
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="share">Raw Share Key</param>
            /// <returns></returns>
            public static string SecureIdentity(byte[] share)
            {
                byte[] _key = SHA256.Create().ComputeHash(share);
                return "0199" + RIPEMD160.Create().ComputeHash(_key).ToHex();
            }
            // HMAC using SHA-256 / SHA-384 / SHA-512
            public static string SignHash(byte[] share, byte[] hashBytes)
            {
                HMAC hmac = new HMACSHA256(share);
                return Convert.ToBase64String(hmac.ComputeHash(hashBytes));
            }
            public static bool VerifyHash(byte[] share, byte[] hashBytes, byte[] signature)
            {
                 HMAC hmac = new HMACSHA256(share);
                return hmac.ComputeHash(hashBytes).SequenceEqual(signature);
            }
        }
    }
