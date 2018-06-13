using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tanker
{
    public class SDK
    {

        public static string GenerateUserToken(string userId, string trustchainId, string trustchainPrivateKey)
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

            byte[] randomBuf = Sodium.SodiumCore.GetRandomBytes(Crypto.UserSecretSize - 1);
            byte[] hash = Crypto.GenericHash(Crypto.ConcatByteArrays(randomBuf, hashedUserId), Crypto.CheckHashBlockSize);
            byte[] userSecret = Crypto.ConcatByteArrays(randomBuf, new byte[] { hash[0] });

            UserToken token = new UserToken();
            token.delegation_signature = Convert.ToBase64String(delegationSignature);
            token.ephemeral_private_signature_key = Convert.ToBase64String(ephemeralPrivateKey);
            token.ephemeral_public_signature_key = Convert.ToBase64String(ephemeralPublicKey);
            token.user_secret = Convert.ToBase64String(userSecret);
            token.user_id = Convert.ToBase64String(hashedUserId);

            string asJson = JsonConvert.SerializeObject(token);
            string res = Convert.ToBase64String(Encoding.ASCII.GetBytes(asJson));
            return res;
        }
    }
}
