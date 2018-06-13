using NUnit.Framework;
using System;
using System.Text;
using Newtonsoft.Json;
using System.Linq;

namespace Tanker
{
    public class UserToken
    {
        // Note: those should match the key in the JSON file, 
        // hence the snake case
        public string delegation_signature { get; set; }
        public string ephemeral_private_signature_key { get; set; }
        public string ephemeral_public_signature_key { get; set; }
        public string user_id { get; set; }
        public string user_secret { get; set; }
    }

	public class UserTokenTest
	{
        const string TrustchainId = "AzES0aJwDCej9bQVY9AUMZBCLdX0msEc/TJ4DOhZaQs=";
        const string TrustchainPrivateKey = "cBAq6A00rRNVTHicxNHdDFuq6LNUo6gAz58oKqy9CGd054sGkfPYgXftRCRLfqxeiaoRwQCNLIKxdnuKuf1RAA==";
        const string TrustchainPublicKey = "dOeLBpHz2IF37UQkS36sXomqEcEAjSyCsXZ7irn9UQA=";

        [Test]
        public void SignatureAndUserSecretAreValid()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string delegationSignature = userToken.delegation_signature;

            CheckSignature(
                userToken.ephemeral_public_signature_key, 
                userToken.user_id,
                delegationSignature);

            Assert.IsTrue(CheckUserSecret(userToken.user_id, userToken.user_secret));
        }

        [Test]
        public void InvalidDelegationSignature()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string delegationSignature = userToken.delegation_signature;

            byte[] buf = Convert.FromBase64String(delegationSignature);
            byte[] invalidBuf = CryptoTests.CorruptBuffer(buf);
            string invalidDelegationSignature = Convert.ToBase64String(invalidBuf);

            Assert.Throws(typeof(InvalidSignatureException),
                delegate { CheckSignature(
                    userToken.ephemeral_public_signature_key, 
                    userToken.user_id,
                    invalidDelegationSignature
                    ); } );

        }

        [Test]
        public void InvalidUserSecret()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string userSecret = userToken.user_secret;

            byte[] buf = Convert.FromBase64String(userSecret);
            byte[] invalidBuf = CryptoTests.CorruptBuffer(buf);
            string invalidUserSecret = Convert.ToBase64String(invalidBuf);

            Assert.IsFalse(CheckUserSecret(userToken.user_id, invalidUserSecret));
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

        private void CheckSignature(string encodedEphemeralPublicSignatureKey, string encodedUserId, string encodedSignature)
        {
            byte[] trustchainPublicKey = Convert.FromBase64String(TrustchainPublicKey);
            byte[] ephemeralPublicSignatureKey = Convert.FromBase64String(encodedEphemeralPublicSignatureKey);
            byte[] userId = Convert.FromBase64String(encodedUserId);
            byte[] signature = Convert.FromBase64String(encodedSignature);

            byte[] signedData = Crypto.ConcatByteArrays(ephemeralPublicSignatureKey, userId);

            Crypto.VerifySignDetached(signedData, signature, trustchainPublicKey);
        }

        private bool CheckUserSecret(string encodedUserId, string encodedUserSecret)
        {
            byte[] hashedUserId = Convert.FromBase64String(encodedUserId);
            byte[] userSecret = Convert.FromBase64String(encodedUserSecret);

            Assert.AreEqual(Crypto.BlockHashSize, hashedUserId.Length);
            Assert.AreEqual(Crypto.UserSecretSize, userSecret.Length);

            byte[] truncatedUserSecret = userSecret.Take(Crypto.UserSecretSize - 1).ToArray<byte>();
            byte[] toHash = Crypto.ConcatByteArrays(truncatedUserSecret, hashedUserId);

            byte[] control = Crypto.GenericHash(toHash, Crypto.CheckHashBlockSize);
            return userSecret[Crypto.UserSecretSize - 1] == control[0];
        }

    }
}
