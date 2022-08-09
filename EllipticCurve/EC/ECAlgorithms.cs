using ECC.NET;

namespace EllipticCurve.EC
{
    public static class ECAlgorithms
    {
        /// <summary>
        /// Algorithm for creating common secret key for two parties: Alice and Bob.
        /// </summary>
        /// <param name="alice">Party Alice.</param>
        /// <param name="bob">Party Bob.</param>
        public static void ECDH(out PartyEC alice, out PartyEC bob)
        {
            // Let's choose "standart" elliptic curve nistp256. Can be choosen another one.
            Curve curve = new Curve(Curve.CurveName.nistp256);

            // Creating of two party sides.
            alice = new PartyEC(curve);
            bob = new PartyEC(curve);

            // Generating public and private keys for Alice and Bob .
            alice.GeneratePairOfKeys();
            bob.GeneratePairOfKeys();

            // Getting public keys and calculating of secret keys.
            alice.CalculateSecretKey(bob.PublicKey);
            bob.CalculateSecretKey(alice.PublicKey);
        }
    }
}
