using NUnit.Framework;
using System;
using System.Text;
using Tanker.Crypto;

namespace Tanker
{
    namespace Crypto
    {
        internal class Tests
        {
            [Test]
            public void TestHash()
            {
                string hexVector = "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923";
                byte[] expected = CryptoCore.FromHex(hexVector);

                byte[] toHash = Encoding.ASCII.GetBytes("abc");
                byte[] actual = CryptoCore.GenericHash(toHash, 64);

                Assert.AreEqual(actual, expected);
            }

            [Test]
            public void TestSignValidSignature()
            {
                byte[] message = Encoding.ASCII.GetBytes("message");
                var keyPair = CryptoCore.SignKeyPair();
                byte[] signature = CryptoCore.SignDetached(message, keyPair.PrivateKey);

                Assert.IsTrue(CryptoCore.VerifySignDetached(message, signature, keyPair.PublicKey));
            }

            [Test]
            public void TestSignInvalidMessage()
            {
                byte[] message = Encoding.ASCII.GetBytes("message");
                var keyPair = CryptoCore.SignKeyPair();
                byte[] signature = CryptoCore.SignDetached(message, keyPair.PrivateKey);

                byte[] invalidMessage = Encoding.ASCII.GetBytes("m3ssage");

                Assert.IsFalse(CryptoCore.VerifySignDetached(invalidMessage, signature, keyPair.PublicKey));
            }

            [Test]
            public void TestInvalidSignature()
            {
                byte[] message = Encoding.ASCII.GetBytes("message");
                var keyPair = CryptoCore.SignKeyPair();
                byte[] signature = CryptoCore.SignDetached(message, keyPair.PrivateKey);
                byte[] invalidSignature = CorruptBuffer(signature);
                Assert.IsFalse(CryptoCore.VerifySignDetached(message, invalidSignature, keyPair.PublicKey));
            }

            public static byte[] CorruptBuffer(byte[] buffer)
            {
                byte[] res = buffer;
                res[0] = buffer[0] = 1;
                return res;
            }
        }
    }
}
