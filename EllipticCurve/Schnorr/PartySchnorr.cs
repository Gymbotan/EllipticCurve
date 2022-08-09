using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EllipticCurve.Schnorr
{
    /// <summary>
    /// Person who use Schnorr scheme.
    /// </summary>
    public class PartySchnorr
    {
        /// <summary>
        /// Schnorr scheme.
        /// </summary>
        public SchnorrScheme Scheme { get; private set; }

        /// <summary>
        /// Public key.
        /// </summary>
        public BigInteger PublicKey { get; private set; }

        /// <summary>
        /// Private key.
        /// </summary>
        private BigInteger privateKey;

        /// <summary>
        /// Create object of PartySchnorr.
        /// </summary>
        /// <param name="scheme"></param>
        public PartySchnorr(SchnorrScheme scheme)
        {
            if (scheme is null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }

            Scheme = scheme;
        }

        /// <summary>
        /// Generate public and private keys.
        /// </summary>
        public void GenerateKeys()
        {
            // Check are keys already exist?

            int keyBytes = Scheme.Q.GetByteCount();

            byte[] randomBytes = new byte[keyBytes];

            RandomNumberGenerator generator = RandomNumberGenerator.Create();

            do
            {
                generator.GetBytes(randomBytes);

                BigInteger randomValue = new BigInteger(randomBytes);
                privateKey = randomValue % Scheme.Q;
                while (privateKey < 0) // privateKey should be positive
                {
                    privateKey = (privateKey + Scheme.Q) % Scheme.Q;
                }
            }
            while (privateKey == 0);

            PublicKey = BigInteger.ModPow(Scheme.G, Scheme.Q - privateKey, Scheme.P);
        }

        /// <summary>
        /// Calculating signsture for message.
        /// </summary>
        /// <param name="message">Message to sign.</param>
        /// <returns>Digital signature (e, y).</returns>
        public (BigInteger, BigInteger) SignMessage(BigInteger message)
        {
            if (privateKey == 0)
            {
                throw new ArgumentException("Private key is not exists.");
            }

            BigInteger randomR = GetRandomValue(Scheme.Q);

            BigInteger x = BigInteger.ModPow(Scheme.G, randomR, Scheme.P);
            BigInteger concatValue = BigInteger.Parse(message.ToString() + x.ToString());

            BigInteger e = Scheme.CalculateHash(concatValue);
            BigInteger y = (randomR + e * privateKey) % Scheme.Q;
            return (e, y);
        }

        /// <summary>
        /// Signature verification.
        /// </summary>
        /// <param name="scheme">Schnorr scheme used.</param>
        /// <param name="message">Message.</param>
        /// <param name="signature">Signature.</param>
        /// <param name="publicKey">Public key.</param>
        /// <returns>Is signature correct.</returns>
        public bool SignatureVerifying (SchnorrScheme scheme, BigInteger message, (BigInteger, BigInteger) signature, BigInteger publicKey)
        {
            BigInteger x = (BigInteger.ModPow(scheme.G, signature.Item2, scheme.P) *
                BigInteger.ModPow(publicKey, signature.Item1, scheme.P)) % scheme.P;

            BigInteger concatValue = BigInteger.Parse(message.ToString() + x.ToString());
            BigInteger hash = scheme.CalculateHash(concatValue);

            return hash == signature.Item1;
        }

        public static BigInteger GetRandomValue(BigInteger module)
        {
            BigInteger randomVal;
            int keyBytes = module.GetByteCount();
            byte[] randomBytes = new byte[keyBytes];
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            do
            {
                generator.GetBytes(randomBytes);

                BigInteger randomValue = new BigInteger(randomBytes);
                randomVal = (randomValue % module);
                while (randomVal < 0) // randomR should be positive
                {
                    randomVal = (randomVal + module) % module;
                }
            }
            while (randomVal == 0);
            return randomVal;
        }
    }
}
