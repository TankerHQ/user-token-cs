using NUnit.Framework;
using Sodium;

namespace Tanker
{ 
	public class UserTokenTest
	{
        [Test]
        public void TestZero()
        {
            Assert.AreEqual(42, 40 + 2);
        }

        [Test]
        public void TestSodiumVersion()
        {
            string actual = SodiumCore.SodiumVersionString();
            Assert.AreEqual("1.0.11", actual);
        }

    }
}
