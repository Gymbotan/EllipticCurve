using EllipticCurve.Schnorr;
using NUnit.Framework;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace EllipticCurveTests
{
    public class SchnorrTests
    {
        [TestCase("12345")]
        [TestCase("28475637484")]
        [TestCase("9996664442221111")]
        public void SchnorrScheme_CorrectWork(string mes)
        {
            SchnorrScheme scheme = new SchnorrScheme();

            PartySchnorr alice = new PartySchnorr(scheme);
            alice.GenerateKeys();
            BigInteger message = BigInteger.Parse(mes);
            var schnorrSignature = alice.SignMessage(message);
            Console.WriteLine($"\nSchnorr signature for message \'{message}\': " + schnorrSignature);
            PartySchnorr bob = new PartySchnorr(scheme);
            
            Assert.AreEqual(true, bob.SignatureVerifying(scheme, message, schnorrSignature, alice.PublicKey));
        }

        [Test]
        public void SchnorrSchemeCreating_NullHashAlgorithm_ThrowArgumentNullException()
        {
            HashAlgorithm algorithm = null;
            Assert.Throws<ArgumentNullException>(() => new SchnorrScheme(48731, 443, 11444, algorithm));
        }

        [TestCase(-12)]
        [TestCase(48733)]
        public void SchnorrSchemeCreating_IncorrectGParameter_ThrowArgumentOutOfRangeException(int g)
        {
            HashAlgorithm algorithm = new SHA512Managed();
            Assert.Throws<ArgumentOutOfRangeException>(() => new SchnorrScheme(48731, 443, g, algorithm));
        }

        [TestCase(12)]
        [TestCase(49)]
        [TestCase(129)]
        public void SchnorrSchemeCreating_IncorrectGParameter_ThrowException(int g)
        {
            HashAlgorithm algorithm = new SHA512Managed();
            Assert.Throws<ArgumentException>(() => new SchnorrScheme(48731, 443, g, algorithm));
        }

        [Test]
        public void SchnorrSchemeCreating_CorrectCreation()
        {
            HashAlgorithm algorithm = new SHA512Managed();
            Assert.DoesNotThrow(() => new SchnorrScheme(48731, 443, 11444, algorithm), "Schnorr scheme created correctly");
        }
    }
}
