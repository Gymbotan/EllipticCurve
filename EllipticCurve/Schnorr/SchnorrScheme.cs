using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace EllipticCurve.Schnorr
{
    /// <summary>
    /// Schnorr scheme. Contains main values: P, Q, G, Hash algorithm.
    /// </summary>
    public class SchnorrScheme
    {
        /// <summary>
        /// Prime number P.
        /// </summary>
        public BigInteger P { get; private set; }

        /// <summary>
        /// Prime number Q.
        /// </summary>
        public BigInteger Q { get; private set; }

        /// <summary>
        /// Prime number G.
        /// </summary>
        public BigInteger G { get; private set; }

        /// <summary>
        /// Hash algorithm used in scheme.
        /// </summary>
        public HashAlgorithm HashAlg { get; private set; }

        public SchnorrScheme()
        {
            P = BigInteger.Parse("0B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", NumberStyles.HexNumber);
            Q = BigInteger.Parse("0F518AA8781A8DF278ABA4E7D64B7CB9D49462353", NumberStyles.HexNumber);
            G = BigInteger.Parse("0A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", NumberStyles.HexNumber);
            HashAlg = new SHA512Managed();
        }

        public SchnorrScheme(BigInteger p, BigInteger q, BigInteger g, HashAlgorithm algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (g < 1 || g > p)
            {
                throw new ArgumentOutOfRangeException(nameof(g));
            }

            if (BigInteger.ModPow(g, q, p) != 1)
            {
                throw new ArgumentException("g^q != 1 mod p");
            }

            P = p;
            Q = q;
            G = g;
            HashAlg = algorithm;
        }

        /// <summary>
        /// Hash calculation.
        /// </summary>
        /// <param name="message">message.</param>
        /// <returns>Hash value.</returns>
        public BigInteger CalculateHash (BigInteger message)
        {
            byte[] data = message.ToByteArray();
            byte[] result;
            result = HashAlg.ComputeHash(data);
            BigInteger hash = new BigInteger(result);

            if (hash < 0)
            {
                hash = -hash;
            }
            return hash;
        }
    }
}
