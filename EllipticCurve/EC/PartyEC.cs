using ECC.NET;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace EllipticCurve.EC
{
    /// <summary>
    /// Party (or side) of DH key exchange protocol.
    /// </summary>
    public partial class PartyEC
    {
        /// <summary>
        /// Elliptic curve гув in DH exchange protocol.
        /// </summary>
        public Curve Curve { get; private set; }

        /// <summary>
        /// Base point of elliptic curve.
        /// </summary>
        public Point BasePoint { get; private set; }

        /// <summary>
        /// Private key.
        /// </summary>
        private BigInteger PrivateKey { get; set; }

        /// <summary>
        /// Public key.
        /// </summary>
        public Point PublicKey { get; private set; }

        /// <summary>
        /// Common secret key.
        /// </summary>
        private Point SecretKey { get; set; }

        public PartyEC(Curve curve)
        {
            if (curve is null)
            {
                throw new ArgumentNullException(nameof(curve));
            }

            Curve = curve;
            BasePoint = curve.G;
        }

        /// <summary>
        /// Generate randomly private key and corresponding public key for this party.
        /// </summary>
        public void GeneratePairOfKeys()
        {
            uint keyBytes = Curve.Length / 8;

            byte[] randomBytes = new byte[keyBytes];

            RandomNumberGenerator generator = RandomNumberGenerator.Create();

            do
            {
                generator.GetBytes(randomBytes);

                BigInteger randomValue = new BigInteger(randomBytes);
                randomValue = randomValue > 0 ? randomValue : -randomValue;
                PrivateKey = randomValue % Curve.N;
            }
            while (PrivateKey == 0);

            PublicKey = Point.Multiply(PrivateKey, BasePoint);
        }

        /// <summary>
        /// Calculate secret key by getting EC point from another party.
        /// </summary>
        /// <param name="point">EC point from another party.</param>
        public void CalculateSecretKey(Point point)
        {
            if (point is null)
            {
                throw new ArgumentNullException(nameof(point));
            }

            SecretKey = Point.Multiply(PrivateKey, point);
        }

        /// <summary>
        /// Return common secret key to check that everything work correctly. 
        /// Should be deleted after checking. to not to spoil secret key.
        /// </summary>
        /// <returns>Secret key.</returns>
        public Point GetSecretKey() => SecretKey;

        /// <summary>
        /// ECDSA generation according to https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        /// </summary>
        /// <param name="message">Message to sign.</param>
        /// <returns>Digital signature (r,s).</returns>
        public (BigInteger, BigInteger) ECDSAGeneration(BigInteger message)
        {
            // steps 1,2
            BigInteger z = calculateZ(message, Curve.N);

            // step 3
            RandomNumberGenerator generator = RandomNumberGenerator.Create();
            BigInteger k, r, s;
            uint keyBytes = Curve.Length / 8;

            byte[] randomBytes = new byte[keyBytes];
            do
            {
                do
                {
                    do
                    {
                        generator.GetBytes(randomBytes);

                        BigInteger randomValue = new BigInteger(randomBytes);
                        k = randomValue > 0 ? randomValue : -randomValue;
                        k = k % Curve.N;
                    }
                    while (k == 0);

                    // step 4
                    BigInteger x1 = Point.Multiply(k, Curve.G).X;
                    r = x1 % Curve.N;
                    while (r < 0) // r should be a positive number.
                    {
                        r = (r + Curve.N) % Curve.N;
                    }
                }
                while (r == 0); // step 5

                // step 6
                BigInteger kInverse;
                TryBigModInverse(k, Curve.N, out kInverse);

                s = kInverse * (z + r * PrivateKey + Curve.N) % Curve.N;
                while (s < 0)
                {
                    s = (s + Curve.N) % Curve.N;
                }

            }
            while (s == 0); // step 6 checking

            return (r, s);
        }

        /// <summary>
        /// Verification algorithm of ECDSA.
        /// </summary>
        /// <param name="signature">Digital signature (r,s).</param>
        /// <param name="curve">Elliptic curve used in algorithm.</param>
        /// <param name="publicKeyPoint">Public key of an author.</param>
        /// <param name="message">Message.</param>
        /// <returns>Is the signature correct.</returns>
        public bool ECDSAVerification((BigInteger r, BigInteger s) signature, Curve curve, Point publicKeyPoint, BigInteger message)
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
            if (signature.r < 1 || signature.r >= curve.N)
            {
                return false;
            }

            if (signature.s < 1 || signature.s >= curve.N)
            {
                return false;
            }

            // steps 2, 3
            BigInteger z = calculateZ(message, curve.N);

            // step 4
            BigInteger sInverse;
            TryBigModInverse(signature.s, curve.N, out sInverse);

            BigInteger u1 = (z * sInverse) % curve.N;
            BigInteger u2 = (signature.r * sInverse) % curve.N;

            // step 5
            Point point = Point.Add(Point.Multiply(u1, curve.G), Point.Multiply(u2, publicKeyPoint));

            // step 6
            return point.X % curve.N == signature.r;
        }

        /// <summary>
        /// Calculate inverse value for choosen number in multiplicative group.
        /// </summary>
        /// <param name="number">Choosen number.</param>
        /// <param name="module">Module.</param>
        /// <param name="result">Inverse value.</param>
        /// <returns>Can calculate or not.</returns>
        public static bool TryBigModInverse(BigInteger number, BigInteger module, out BigInteger result)
        {
            if (number < 1) throw new ArgumentOutOfRangeException(nameof(number));
            if (module < 2) throw new ArgumentOutOfRangeException(nameof(module));
            BigInteger n = number;
            BigInteger m = module, v = 0, d = 1;
            while (n > 0)
            {
                BigInteger t = m / n, x = n;
                n = m % x;
                m = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            result = v % module;
            if (result < 0) result += module;
            if (number * result % module == 1) return true;
            result = default;
            return false;
        }

        /// <summary>
        /// Calculate leftmost bits of Hash of message (steps 1, 2 of ECDSA algorithm).
        /// </summary>
        /// <param name="message">Message (scalar number).</param>
        /// <param name="curveOrder">Orger of elliptic curve.</param>
        /// <returns>Calculated value.</returns>
        public static BigInteger calculateZ(BigInteger message, BigInteger curveOrder)
        {
            // step 1
            byte[] data = message.ToByteArray();
            byte[] result;
            SHA512 shaM = new SHA512Managed();
            result = shaM.ComputeHash(data);
            BigInteger e = new BigInteger(result);

            // step 2
            long eSize = e.GetBitLength();
            long orderSize = curveOrder.GetBitLength();

            BigInteger z;
            if (eSize < orderSize)
            {
                z = e;
            }
            else
            {
                int shift = checked((int)(eSize - orderSize));
                z = e >> shift;
            }
            return z;
        }
    }
}
