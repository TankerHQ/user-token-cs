using NUnit.Framework;
using Sodium;
using System;
using System.Text;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Tanker
{
    public class UserToken
    {
        public string delegation_signature { get; set; }
        public string ephemeral_private_signature_key { get; set; }
        public string ephemeral_public_signature_key { get; set; }
        public string user_id { get; set; }
        public string user_secret { get; set; }
    }

	public class UserTokenTest
	{
        const string TrustchainId = "toto";
        const string TrustchainPrivateKey = "deadbeef";
        const string TrustchainPublicKey = "pub";

        [Test]
        public void HappyToken()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string delegationSignature = userToken.delegation_signature;

            CheckSignature(TrustchainPublicKey, userToken, delegationSignature);
        }


        private string GenerateTestToken()
        {
            string userId = "steve@tanker.io";
            string token = SDK.GenerateUserToken(userId,
                TrustchainId,
                TrustchainPrivateKey);
            return token;
        }
        
        private UserToken ParseBase64Token(string token)
        {
            byte[] data = Convert.FromBase64String(token);
            string jsonText = Encoding.ASCII.GetString(data);
            return JsonConvert.DeserializeObject<UserToken>(jsonText);
        }

        private void CheckSignature(string publicKey, UserToken token, string signature)
        {
        }


    }
}
