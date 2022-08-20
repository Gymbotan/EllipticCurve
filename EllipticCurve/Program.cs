using System;
using ECC.NET;
using System.Numerics;
using EllipticCurve.Schnorr;
using EllipticCurve.EC;

namespace EllipticCurve
{
    static class Program
    {
        static void Main(string[] args)
        {
            //ECDH
            PartyEC alice, bob;
            ECAlgorithms.ECDH(out alice, out bob);
            Console.WriteLine("ECDH");
            Console.WriteLine("After using DHCA algorithm parties have next common secret key:");
            Console.WriteLine($"Alice: {alice.GetSecretKey()}");
            Console.WriteLine($"Bob:   {bob.GetSecretKey()}");


            // ECDSA
            Console.WriteLine("\n\nECDSA");

            // Let's choose "standart" elliptic curve nistp256. Can be choosen another one.
            Curve curve = new Curve(Curve.CurveName.nistp256);

            // Creating of party side Carrol.
            PartyEC carrol = new PartyEC(curve);
            PartyEC daniel = new PartyEC(curve);

            carrol.GeneratePairOfKeys();
            BigInteger message = 123456789;
            var signature = carrol.ECDSAGeneration(message);

            Console.WriteLine($"For message \'123456789\' the signature is {signature}.");
            Console.WriteLine($"Is it correct? {daniel.ECDSAVerification(signature, curve, carrol.PublicKey, message)}");

            message = 987654321;
            Console.WriteLine($"Is it correct for another message? {daniel.ECDSAVerification(signature, curve, carrol.PublicKey, message)}");


            //SchnorrEC
            Console.WriteLine("\n\nSchnorr EC scheme");
            PartyEC eva = new PartyEC(curve);
            PartyEC fox = new PartyEC(curve);
            eva.GeneratePairOfKeys();
            message = 123456789;

            var schnorrECSignature = eva.SchnorrECGeneration(message);
            Console.WriteLine($"SchnorrEC signature for message \'{message}\': " + schnorrECSignature);
            Console.WriteLine($"\nIs SсhnorrEC signature correct? {fox.SchnorrECVerification(schnorrECSignature, curve, eva.PublicKey, message)}");

            message = 987654321;
            Console.WriteLine($"Is it correct for another message? {fox.SchnorrECVerification(schnorrECSignature, curve, eva.PublicKey, message)}");


            // Schnorr
            Console.WriteLine("\n\nSchnorr scheme");
            SchnorrScheme scheme = new SchnorrScheme();

            PartySchnorr Alice = new PartySchnorr(scheme);
            Alice.GenerateKeys();
            message = 123456789;
            var schnorrSignature = Alice.SignMessage(message);
            Console.WriteLine($"Schnorr signature for message \'{message}\': " + schnorrSignature);
            PartySchnorr Bob = new PartySchnorr(scheme);
            Console.WriteLine($"\nIs Sсhnorr signature correct? {Bob.SignatureVerifying(scheme, message, schnorrSignature, Alice.PublicKey)}");

            message = 987654321;
            Console.WriteLine($"Is it correct for another message? {Bob.SignatureVerifying(scheme, message, schnorrSignature, Alice.PublicKey)}");

            Console.ReadLine();
        }
    }
}
