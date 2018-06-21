using Newtonsoft.Json;
using System;
using System.Text;
using Tanker.Crypto;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Tanker.UserToken.Test")]

namespace Tanker
{
    public class UserToken
    {
        [JsonProperty(PropertyName = "delegation_signature")]
        public string DelegationSignature { protected internal get; set; }
        [JsonProperty(PropertyName = "ephemeral_private_signature_key")]
        public string EphemeralPrivateSignatureKey { protected internal get; set; }
        [JsonProperty(PropertyName = "ephemeral_public_signature_key")]
        public string EphemeralPublicSignatureKey { protected internal get; set; }
        [JsonProperty(PropertyName = "user_id")]
        public string UserId { protected internal get;  set; }
        [JsonProperty(PropertyName = "user_secret")]
        public string UserSecret { protected internal get; set; }

        public UserToken() { }

        public UserToken(string trustchainId, string trustchainPrivateKey, string userId)
        {
            byte[] trustchainIdBuf = Convert.FromBase64String(trustchainId);
            byte[] trustchainPrivateKeyBuf = Convert.FromBase64String(trustchainPrivateKey);

            byte[] userIdBuf = Encoding.Unicode.GetBytes(userId);
            var toHash = CryptoCore.ConcatByteArrays(userIdBuf, trustchainIdBuf);
            byte[] hashedUserId = CryptoCore.GenericHash(toHash, CryptoCore.BlockHashSize);

            var keyPair = CryptoCore.SignKeyPair();
            byte[] ephemeralPrivateKey = keyPair.PrivateKey;
            byte[] ephemeralPublicKey = keyPair.PublicKey;
            byte[] toSign = CryptoCore.ConcatByteArrays(ephemeralPublicKey, hashedUserId);
            byte[] delegationSignature = CryptoCore.SignDetached(toSign, trustchainPrivateKeyBuf);

            byte[] randomBuf = CryptoCore.RandomBytes(CryptoCore.UserSecretSize - 1);
            byte[] hash = CryptoCore.GenericHash(CryptoCore.ConcatByteArrays(randomBuf, hashedUserId), CryptoCore.CheckHashBlockSize);
            byte[] userSecret = CryptoCore.ConcatByteArrays(randomBuf, new byte[] { hash[0] });

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
