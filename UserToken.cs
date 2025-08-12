
    public class UserToken
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
         public long counter { get; set; }
         public byte[] share { get; set; }
         public string jwToken { get; set; }
         public bool? isProtected { get; set; } //  encrypted setupcode
     }
     public static long BytesToLong(byte[] bytes)
     {
         long l = BitConverter.ToInt64(bytes, 0);
         return System.Math.Abs(l);
     }
     public static byte[] LongToBytes(long value)
     {
         ulong _value = (ulong)value;

         return BitConverter.IsLittleEndian
             ? new[] { (byte)((_value >> 56) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)(_value & 0xFF) }
             : new[] { (byte)(_value & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 56) & 0xFF) };
     }
     /// <summary>
     /// Credit Authorisation via a PayMeToken
     /// </summary>
     /// <param name="tokenPath">User Token</param>
     /// <param name="amount">Payment Amount in LCU</param>
     /// <returns></returns>
     /// <exception cref="Exception"></exception>
     public static string PayMeToken(string tokenPath, decimal amount)
     {
         RecoveryResponse rsp = UserToken.GetUserToken(tokenPath);
         // Extract Function endpoint from Token
         var securityToken = new JwtSecurityToken(rsp.jwToken);
         Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
         string _secureIdentity = securityToken.Claims.FirstOrDefault(x => x.Type == "SecureIdentity").Value;
         string samount = amount.ToString("N2");
         HttpClient _httpClient = new HttpClient();
         string _relativeUrl = "Coin/IssuePayMeToken?amount=" + samount;
         Uri _uri = new Uri(_baseUri, _relativeUrl);
         _httpClient.BaseAddress = _baseUri;
         _httpClient.DefaultRequestHeaders.Add("x-token", rsp.jwToken);
         // Add client JwSignature
         byte[] hashBytes = Encoding.UTF8.GetBytes(_secureIdentity + samount);
         string ssign = HmacProvider.SignHash(_secureIdentity, rsp.share, hashBytes, rsp.counter);
         _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
         HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
         string payMeToken = string.Empty;
         if (response.IsSuccessStatusCode)
         {
             payMeToken = response.Content.ReadAsStringAsync().Result;
         }
         else if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
         {
             // Sync issue detected -> resync
             RecoveryResponse r = user_TokenRefresh(rsp);
             r.isProtected = false; // unprotected from refresh
             // Save 
             SaveUserToken(tokenPath, r);

         }
         else
         {
             string sError = response.Content.ReadAsStringAsync().Result;
             throw new Exception(sError);
         }

         // Increment
         UserToken.IncrementCounter(tokenPath);
         return payMeToken;
     }
     /// <summary>
     /// Debit authorisation via a funtion Token
     /// </summary>
     /// <param name="tokenPath">Debitor User Token</param>
     /// <param name="hashBytes">Debit Hashbytes</param>
     /// <returns></returns>
     /// <exception cref="Exception"></exception>

     public static string SignHash(string tokenPath, byte[] hashBytes)
     {
         RecoveryResponse rsp = UserToken.GetUserToken(tokenPath);
         // Extract Function endpoint from Token
         var securityToken = new JwtSecurityToken(rsp.jwToken);
         Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
         string _secureIdentity = securityToken.Claims.FirstOrDefault(x => x.Type == "SecureIdentity").Value;
       
         // Obtain Function JwToken
         HttpClient _httpClient = new HttpClient();
         // Build funtion endpoint Uri
         string _relativeUrl = "User/SignHash";
         Uri _uri = new Uri(_baseUri, _relativeUrl);
         _httpClient.BaseAddress = _baseUri;
         _httpClient.DefaultRequestHeaders.Add("x-token", rsp.jwToken);
          // Add client JwSignature
         string ssign = HmacProvider.SignHash(_secureIdentity,rsp.share, hashBytes, rsp.counter);
         _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
         string functionToken = string.Empty;
         HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
         if (response.IsSuccessStatusCode)
         {
             // Increment Counter
             IncrementCounter(tokenPath);
             functionToken = response.Content.ReadAsStringAsync().Result;
         }
         else if(response.StatusCode == System.Net.HttpStatusCode.Conflict)
         {
             // Sync issue detected -> resync
             RecoveryResponse r = user_TokenRefresh(rsp);
             r.isProtected = false; // unprotected from refresh
             // Save 
             SaveUserToken(tokenPath, r);

         }
         else
         {
             string sError = response.Content.ReadAsStringAsync().Result;
             throw new Exception(sError);
         }
         // Increment
         UserToken.IncrementCounter(tokenPath);
         return functionToken;
     }

     public static RecoveryResponse GetUserToken(string userTokenPath)
     {
         string sToken = System.IO.File.ReadAllText(userTokenPath);
         UserToken.RecoveryResponse rsp = System.Text.Json.JsonSerializer.Deserialize<RecoveryResponse>(sToken);
         // Check protected
         if (rsp.isProtected.HasValue == false || rsp.isProtected == false)
         {

             // Always protect
             rsp.isProtected = true;
             byte[] encCode = Protect(rsp.share);
             // Check 
             byte[] pCode = UnProtect(encCode);
             if (pCode != rsp.share)
                 throw new Exception("Setupcode different");
             rsp.share = encCode;
             // Save with encypted setupcode
             string json = System.Text.Json.JsonSerializer.Serialize<RecoveryResponse>(rsp);
             System.IO.File.WriteAllText(userTokenPath, json);
             // Return plaintext
             rsp.share = pCode;

         }
         else if (rsp.isProtected == true)
         {
             byte[] pCode = UnProtect(rsp.share);
             rsp.share = pCode;
         }
         // Check expire exp
         var securityToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(rsp.jwToken);
         var issuedAt = securityToken.IssuedAt;
         var validTo = securityToken.ValidTo;
         // Check refresh window 2 days before expired
         if (DateTime.UtcNow >= validTo.AddDays(-2))
         {
             RecoveryResponse r = user_TokenRefresh(rsp);
             securityToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(r.jwToken);
             issuedAt = securityToken.IssuedAt;
             validTo = securityToken.ValidTo;

             // Update UserToken
             rsp.jwToken = r.jwToken;
             rsp.share = r.share; // Mandatory refresh
             r.isProtected = false; // unprotected from refresh
             rsp.counter = r.counter;
             // Save 
             SaveUserToken(userTokenPath, r);
         }
         return rsp;
     }
     public static int GetCounter(string userTokenPath)
     {
         // Serialise
         JsonSerializerOptions jso = new JsonSerializerOptions();
         jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
         string sToken = System.IO.File.ReadAllText(userTokenPath);
         RecoveryResponse rsp = System.Text.Json.JsonSerializer.Deserialize<RecoveryResponse>(sToken, jso);
         return  (int)rsp.counter;
     }
     public static void IncrementCounter(string userTokenPath)
     {
         // Serialise
         JsonSerializerOptions jso = new JsonSerializerOptions();
         jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
         string sToken = System.IO.File.ReadAllText(userTokenPath);
         RecoveryResponse rsp = System.Text.Json.JsonSerializer.Deserialize<RecoveryResponse>(sToken, jso);
         rsp.counter = rsp.counter +1;
         // Save
         string json = System.Text.Json.JsonSerializer.Serialize<RecoveryResponse>(rsp, jso);
         System.IO.File.WriteAllText(userTokenPath, json);

     }
     public static void SaveUserToken(string userTokenPath, RecoveryResponse rsp)
     {
         // Encrypt setupcode
         // Check protected
         if (rsp.isProtected.HasValue == false || rsp.isProtected == false)
         {
             // setupcode in plaintext. so protect
             rsp.share = Protect(rsp.share);
             rsp.isProtected = true;
         }
         // Serialise
         JsonSerializerOptions jso = new JsonSerializerOptions();
         jso.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
         string json = System.Text.Json.JsonSerializer.Serialize<RecoveryResponse>(rsp, jso);
         System.IO.File.WriteAllText(userTokenPath, json);

     }
     public static string BuildUrlWithQueryStringUsingUriBuilder(string basePath, Dictionary<string, string> queryParams)
     {
         var uriBuilder = new UriBuilder(basePath)
         {
             Query = string.Join("&", queryParams.Select(kvp => $"{kvp.Key}={kvp.Value}"))
         };
         return uriBuilder.Uri.AbsoluteUri;
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
     public static RecoveryResponse user_TokenRefresh(RecoveryResponse r)
     {

         // Extract Function endpoint from User Token
         var securityToken = new JwtSecurityToken(r.jwToken);
         var claim = securityToken.Claims.FirstOrDefault(x => x.Type == "SecureIdentity");
         string _secureIdentity = claim.Value;
         claim = securityToken.Claims.FirstOrDefault(x => x.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti);
         string _jti = claim.Value;
         Uri _baseUri = new Uri(securityToken.Audiences.FirstOrDefault());
         // Obtain Function JwToken
         HttpClient _httpClient = new HttpClient();
         // Build funtion endpoint Uri
         string _relativeUrl = "User/TokenRefresh";
         Uri _uri = new Uri(_baseUri, _relativeUrl);
         _httpClient.BaseAddress = _baseUri;
         // Add User Jwtoken
         _httpClient.DefaultRequestHeaders.Add("x-token", r.jwToken);
         // Add Jws 
         byte[] hashBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(_secureIdentity + _jti));
         string ssign = HmacProvider.SignHash(_secureIdentity, hashBytes, hashBytes);
         _httpClient.DefaultRequestHeaders.Add("x-jws-signature", ssign);
         // Get response
         HttpResponseMessage response = _httpClient.GetAsync(_uri).Result;
         if (response.IsSuccessStatusCode)
         {
             // pass
             string json = response.Content.ReadAsStringAsync().Result;
             // New Rec
             return System.Text.Json.JsonSerializer.Deserialize<RecoveryResponse>(json);
         }
         else
         {
             // fail
             string error = response.Content.ReadAsStringAsync().Result;
             throw new Exception(error);
         }
     }
   
 }
    public class Base64Url
    {
        public static string Encode(byte[] input)
        {
            return Convert.ToBase64String(input).Split('=')[0].Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Decode(string input)
        {
            string text = input;
            text = text.Replace('-', '+'); // 62nd char of encoding
            text = text.Replace('_', '/'); // 63rd char of encoding
            switch (text.Length % 4) // Pad with trailing '='s
            {
                case 2: // Two pad chars
                    text += "==";
                    break;
                case 3: // One pad char
                    text += "=";
                    break;
                case 0: // No pad chars in this case
                    break;
                default:
                    throw new ArgumentOutOfRangeException("input", "Illegal base64url string!");

            }

            return Convert.FromBase64String(text);
        }
    }
    public class HmacProvider
    {
             
        // HMAC using SHA-256 / SHA-384 / SHA-512
        public static string SignHash(byte[] data, byte[] hashBytes)
        {
           
            HMAC hmac = new HMACSHA256(data);
            return Convert.ToBase64String(hmac.ComputeHash(hashBytes));
        }
        public static bool VerifyHash(byte[] data, byte[] hashBytes, byte[] signature)
        {
          
            HMAC hmac = new HMACSHA256(data);
            return hmac.ComputeHash(hashBytes).SequenceEqual(signature);
        }
    }


