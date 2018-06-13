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
        public const int BlockHashSize = 32;
        public const int CheckHashBlockSize = 16;
        public const int UserSecretSize = 32;

        public static byte[] ConcatByteArrays(byte[] a, byte[]b)
        {
            byte[] res = new byte[a.Length + b.Length];
            System.Buffer.BlockCopy(a, 0, res, 0, a.Length);
            System.Buffer.BlockCopy(b, 0, res, a.Length, b.Length);
            return res;
        }

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
