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
        private static byte[] ConcatByteArrays(byte[] a, byte[]b)
        {
            byte[] res = new byte[a.Length + b.Length];
            System.Buffer.BlockCopy(a, 0, res, 0, b.Length);
            System.Buffer.BlockCopy(b, 0, res, a.Length, b.Length);
            return res;
        }

        public static string GenerateUserToken(string userId, string trustchainId, string trustchainPrivateKey)
        {
            byte[] trustchainIdBuf = Convert.FromBase64String(trustchainId);
            byte[] privateKeyBuf = Convert.FromBase64String(trustchainPrivateKey);

            byte[] userIdBuf = Encoding.Unicode.GetBytes(userId);

            var toHash = ConcatByteArrays(userIdBuf, trustchainIdBuf);
            byte[] hashedUserId = Crypto.GenericHash(toHash, Crypto.BlockHashSize);

            var keyPair = Crypto.SignKeyPair();

            UserToken token = new UserToken();
            token.delegation_signature = "";
            token.ephemeral_private_signature_key = Convert.ToBase64String(keyPair.PrivateKey);
            token.ephemeral_public_signature_key = Convert.ToBase64String(keyPair.PublicKey);
            token.user_secret = "toto";

            string asJson = JsonConvert.SerializeObject(token);
            string res = Convert.ToBase64String(Encoding.ASCII.GetBytes(asJson));
            return res;
        }
    }
}
