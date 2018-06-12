using System;

namespace Tanker
{
    public class InvalidSignatureException: Exception
    {
        public InvalidSignatureException()
        { }
    }

    public class Crypto
    {
        public static byte[] GenericHash(byte[] message, int size)
        {
            return Sodium.GenericHash.Hash(message, null, size);
        }

        public static Sodium.KeyPair SignKeyPair()
        {
            return Sodium.PublicKeyAuth.GenerateKeyPair();
        }

        public static byte[] SignDetached(byte[] message, byte[] privateKey)
        {
            var signature = Sodium.PublicKeyAuth.SignDetached(message, privateKey);
            return signature;
        }

        public static void VerifySignDetached(byte[] message, byte[] signature, byte[] publicKey)
        {
            var ok = Sodium.PublicKeyAuth.VerifyDetached(signature, message, publicKey);
            if (!ok)
            {
                throw new InvalidSignatureException();
            }
        }
    }
}
