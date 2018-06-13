using Newtonsoft.Json;
using System;
using System.Text;

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

            this.delegation_signature = Convert.ToBase64String(delegationSignature);
            this.ephemeral_private_signature_key = Convert.ToBase64String(ephemeralPrivateKey);
            this.ephemeral_public_signature_key = Convert.ToBase64String(ephemeralPublicKey);
            this.user_secret = Convert.ToBase64String(userSecret);
            this.user_id = Convert.ToBase64String(hashedUserId);

        }

        public string Serialize()
        {
            string asJson = JsonConvert.SerializeObject(this);
            return Convert.ToBase64String(Encoding.ASCII.GetBytes(asJson));
        }

    }

}
