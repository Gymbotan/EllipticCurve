using ECC.NET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EllipticCurve.EC
{
    public partial class PartyEC
    {
        /// <summary>
        /// Digital signature generation algorithm of Schnorr scheme based on elliptic curves. (https://web.stanford.edu/class/cs259c/lectures/schnorr.pdf)
        /// </summary>
        /// <param name="message">Message.</param>
        /// <returns>Digital signature (pointR, s).</returns>
        public (Point, BigInteger) SchnorrECGeneration(BigInteger message)
        {
            // step 1
            uint keyBytes = Curve.Length / 8;

            byte[] randomBytes = new byte[keyBytes];

            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            BigInteger randomK;

            do
            {
                generator.GetBytes(randomBytes);

                BigInteger randomValue = new BigInteger(randomBytes);
                randomK = randomValue > 0 ? randomValue : -randomValue;
                randomK = randomK % Curve.N;
            }
            while (randomK == 0);

            Point pointR = Point.Multiply(randomK, Curve.G);

            // step 2
            BigInteger e = CalculateSHA512Hash(ConcatBigIntAndPoint(message, pointR)); // Can be choosen any hash-function but the same with verification method.

            // step3
            BigInteger s = (randomK + PrivateKey * e) % Curve.N;

            // step 4
            return (pointR, s);
        }

        /// <summary>
        /// Verification algorithm of Schnorr scheme based on elliptic curves.
        /// </summary>
        /// <param name="signature">Digital SchnorrEC signature (r,s).</param>
        /// <param name="curve">Elliptic curve used in algorithm.</param>
        /// <param name="publicKeyPoint">Public key of an author.</param>
        /// <param name="message">Message.</param>
        /// <returns>Is the signature correct.</returns>
        public bool SchnorrECVerification((Point r, BigInteger s) signature, Curve curve, Point publicKeyPoint, BigInteger message)
        {
            if (curve is null)
            {
                throw new ArgumentNullException(nameof(curve));
            }

            // verification that curvePoint is a valid curve point.
            if (Point.IsInfinityPoint(publicKeyPoint))
            {
                return false;
            }

            if (!curve.IsOnCurve(publicKeyPoint))
            {
                return false;
            }

            if (!Point.IsInfinityPoint(Point.Multiply(curve.N, publicKeyPoint)))
            {
                return false;
            }

            // step 1
            BigInteger e = CalculateSHA512Hash(ConcatBigIntAndPoint(message, signature.r)); // Can be choosen any hash-function but the same with verification method.

            // step 2
            Point actualPoint = Point.Add(signature.r, Point.Multiply(e, publicKeyPoint));
            Point expectedPoint = Point.Multiply(signature.s, curve.G);

            return actualPoint.X == expectedPoint.X && actualPoint.Y == expectedPoint.Y;
        }

        private BigInteger ConcatBigIntAndPoint(BigInteger message, Point pointR) =>
            BigInteger.Parse(message.ToString() + pointR.X.ToString() + pointR.Y.ToString());

        /// <summary>
        /// Hash SHA512 calculation.
        /// </summary>
        /// <param name="message">message.</param>
        /// <returns>Hash value.</returns>
        private BigInteger CalculateSHA512Hash(BigInteger message)
        {
            byte[] data = message.ToByteArray();
            byte[] result;

            HashAlgorithm hashAlg = new SHA512Managed();
            result = hashAlg.ComputeHash(data);

            BigInteger hash = new BigInteger(result);
            if (hash < 0)
            {
                hash = -hash;
            }
                        
            return hash;
        }
    }
}
