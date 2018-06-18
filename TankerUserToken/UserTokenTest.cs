using NUnit.Framework;
using System;
using System.Text;
using Newtonsoft.Json;
using System.Linq;
using Tanker.Crypto;


namespace Tanker
{ 

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
            string delegationSignature = userToken.DelegationSignature;

            Assert.IsTrue(CheckSignature(
                userToken.EphemeralPublicSignatureKey, 
                userToken.UserId,
                delegationSignature));

            Assert.IsTrue(CheckUserSecret(userToken.UserId, userToken.UserSecret));
        }

        [Test]
        public void InvalidDelegationSignature()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string delegationSignature = userToken.DelegationSignature;

            byte[] buf = Convert.FromBase64String(delegationSignature);
            byte[] invalidBuf = Crypto.Tests.CorruptBuffer(buf);
            string invalidDelegationSignature = Convert.ToBase64String(invalidBuf);

            Assert.IsFalse(CheckSignature(
                userToken.EphemeralPublicSignatureKey,
                userToken.UserId,
                invalidDelegationSignature));
        }

        [Test]
        public void InvalidUserSecret()
        {
            string encodedToken = GenerateTestToken();
            UserToken userToken = ParseBase64Token(encodedToken);
            string userSecret = userToken.UserSecret;

            byte[] buf = Convert.FromBase64String(userSecret);
            byte[] invalidBuf = Crypto.Tests.CorruptBuffer(buf);
            string invalidUserSecret = Convert.ToBase64String(invalidBuf);

            Assert.IsFalse(CheckUserSecret(userToken.UserId, invalidUserSecret));
        }

        private string GenerateTestToken()
        {
            string userId = "steve@tanker.io";
            var token = new UserToken(TrustchainId, TrustchainPrivateKey, userId);
            return token.Serialize();
        }
        
        private UserToken ParseBase64Token(string token)
        {
            byte[] data = Convert.FromBase64String(token);
            string jsonText = Encoding.ASCII.GetString(data);
            return JsonConvert.DeserializeObject<UserToken>(jsonText);
        }

        private bool CheckSignature(string encodedEphemeralPublicSignatureKey, string encodedUserId, string encodedSignature)
        {
            byte[] trustchainPublicKey = Convert.FromBase64String(TrustchainPublicKey);
            byte[] ephemeralPublicSignatureKey = Convert.FromBase64String(encodedEphemeralPublicSignatureKey);
            byte[] userId = Convert.FromBase64String(encodedUserId);
            byte[] signature = Convert.FromBase64String(encodedSignature);

            byte[] signedData = CryptoCore.ConcatByteArrays(ephemeralPublicSignatureKey, userId);

            return CryptoCore.VerifySignDetached(signedData, signature, trustchainPublicKey);
        }

        private bool CheckUserSecret(string encodedUserId, string encodedUserSecret)
        {
            byte[] hashedUserId = Convert.FromBase64String(encodedUserId);
            byte[] userSecret = Convert.FromBase64String(encodedUserSecret);

            Assert.AreEqual(CryptoCore.BlockHashSize, hashedUserId.Length);
            Assert.AreEqual(CryptoCore.UserSecretSize, userSecret.Length);

            byte[] truncatedUserSecret = userSecret.Take(CryptoCore.UserSecretSize - 1).ToArray<byte>();
            byte[] toHash = CryptoCore.ConcatByteArrays(truncatedUserSecret, hashedUserId);

            byte[] control = CryptoCore.GenericHash(toHash, CryptoCore.CheckHashBlockSize);
            return userSecret[CryptoCore.UserSecretSize - 1] == control[0];
        }
    }
}