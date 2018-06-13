using Newtonsoft.Json;
using System;
using System.Text;

namespace Tanker
{
    public class UserToken
    {
        [JsonProperty(PropertyName = "delegation_signature")]
        public string DelegationSignature { get; set; }
        [JsonProperty(PropertyName = "ephemeral_private_signature_key")]
        public string EphemeralPrivateSignatureKey { get; set; }
        [JsonProperty(PropertyName = "ephemeral_public_signature_key")]
        public string EphemeralPublicSignatureKey { get; set; }
        [JsonProperty(PropertyName = "user_id")]
        public string UserId { get; set; }
        [JsonProperty(PropertyName = "user_secret")]
        public string UserSecret { get; set; }

        public UserToken() { }

        public UserToken(string trustchainId, string trustchainPrivateKey, string userId)
        {
            byte[] trustchainIdBuf = Convert.FromBase64String(trustchainId);
            byte[] trustchainPrivateKeyBuf = Convert.FromBase64String(trustchainPrivateKey);

            byte[] userIdBuf = Encoding.Unicode.GetBytes(userId);
            var toHash = Crypto.ConcatByteArrays(userIdBuf, trustchainIdBuf);
            byte[] hashedUserId = Crypto.GenericHash(toHash, Crypto.BlockHashSize);

            var keyPair = Crypto.SignKeyPair();
            byte[] ephemeralPrivateKey = keyPair.PrivateKey;
            byte[] ephemeralPublicKey = keyPair.PublicKey;
            byte[] toSign = Crypto.ConcatByteArrays(ephemeralPublicKey, hashedUserId);
            byte[] delegationSignature = Crypto.SignDetached(toSign, trustchainPrivateKeyBuf);

            byte[] randomBuf = Crypto.RandomBytes(Crypto.UserSecretSize - 1);
            byte[] hash = Crypto.GenericHash(Crypto.ConcatByteArrays(randomBuf, hashedUserId), Crypto.CheckHashBlockSize);
            byte[] userSecret = Crypto.ConcatByteArrays(randomBuf, new byte[] { hash[0] });

            this.DelegationSignature = Convert.ToBase64String(delegationSignature);
            this.EphemeralPrivateSignatureKey = Convert.ToBase64String(ephemeralPrivateKey);
            this.EphemeralPublicSignatureKey = Convert.ToBase64String(ephemeralPublicKey);
            this.UserSecret = Convert.ToBase64String(userSecret);
            this.UserId = Convert.ToBase64String(hashedUserId);

        }

        public string Serialize()
        {
            string asJson = JsonConvert.SerializeObject(this);
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(asJson));
        }

    }

}
