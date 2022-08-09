using ECC.NET;
using EllipticCurve.EC;
using NUnit.Framework;
using System;
using System.Numerics;

namespace EllipticCurveTests
{
    public class ECTests
    {
        [Test]
        public void ECDH_CorrectWork()
        {
            PartyEC alice, bob;
            ECAlgorithms.ECDH(out alice, out bob);
            Point aliceKey = alice.GetSecretKey();
            Point bobKey = bob.GetSecretKey();
            bool actual = aliceKey.X == bobKey.X && aliceKey.Y == bobKey.Y;

            Assert.AreEqual(true, actual);
        }

        [TestCase(3, 10, ExpectedResult = 7)]
        [TestCase(6, 29, ExpectedResult = 5)]
        [TestCase(4321, 11111, ExpectedResult = 18)]
        public int TryBigModInverse_CorrectWork(int number, int module)
        {
            BigInteger inverseNumber;
            PartyEC.TryBigModInverse(number, module, out inverseNumber);
            return (int)inverseNumber;
        }

        [TestCase(2, 40)]
        [TestCase(111, 999)]
        public void TryBigModInverse_CorrectWork_InverseNotExists(int number, int module)
        {
            BigInteger inverseNumber;
            Assert.AreEqual(false, PartyEC.TryBigModInverse(number, module, out inverseNumber));
        }

        [TestCase(6, -2)]
        [TestCase(-4321, 11111)]
        public void TryBigModInverse_NegativeNumbers_ThrowArgumentOutOfRangeException(int number, int module)
        {
            BigInteger inverseNumber;
            Assert.Throws<ArgumentOutOfRangeException>(() => PartyEC.TryBigModInverse(number, module, out inverseNumber));
        }

        [TestCase("12345")]
        [TestCase("28475637484")]
        [TestCase("9996664442221111")]
        public void ECDSA_CorrectWork(string mes)
        {
            Curve curve = new Curve(Curve.CurveName.nistp256);

            // Creating of party side Carrol.
            PartyEC alice = new PartyEC(curve);
            PartyEC bob = new PartyEC(curve);

            alice.GeneratePairOfKeys();
            BigInteger message = BigInteger.Parse(mes);
            var signature = alice.ECDSAGeneration(message);

            Assert.AreEqual(true, bob.ECDSAVerification(signature, curve, alice.PublicKey, message));
        }
    }
}