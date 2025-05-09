using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinSignatureResult : IBlockResult
    {

        private readonly Oid hashOid;

        private readonly HashAlgorithm hashAlgorithm;

        private readonly AsymmetricAlgorithm privateKey;

        public WinSignatureResult(Oid hashOid, HashAlgorithm hashAlgorithm, AsymmetricAlgorithm privateKey)
        {
            this.hashOid = hashOid;
            this.hashAlgorithm = hashAlgorithm;
            this.privateKey = privateKey;
        }

        public byte[] Collect()
        {
            if (privateKey is RSA rsaKey)
            {
                HashAlgorithmName han;
                switch (hashOid.FriendlyName)
                {
                    case "SHA256":
                        han = HashAlgorithmName.SHA256;
                        break;
                    case "SHA384":
                        han = HashAlgorithmName.SHA384;
                        break;
                    case "SHA512":
                        han = HashAlgorithmName.SHA512;
                        break;
                    default:
                        throw new InvalidOperationException("Hash algorithm not supported :" + hashOid.FriendlyName);
                }
                return rsaKey.SignHash(hashAlgorithm.Hash, han, RSASignaturePadding.Pkcs1);
            }

            if (privateKey is DSA dsaKey)
            {
                return dsaKey.CreateSignature(hashAlgorithm.Hash);
            }

            if (privateKey is ECDsa ecdsaKey)
            {
#if NET5_0_OR_GREATER
                return ecdsaKey.SignHash(hashAlgorithm.Hash, DSASignatureFormat.Rfc3279DerSequence);
#else
                return Ieee1363ToDer(ecdsaKey.SignHash(hashAlgorithm.Hash));
#endif
            }

            throw new InvalidOperationException("Unsuported key type: " + privateKey.GetType());
        }

        public int Collect(byte[] destination, int offset)
        {
            byte[] signature = Collect();
            signature.CopyTo(destination, offset);
            return signature.Length;
        }

        public int GetMaxResultLength()
        {
            //todo::calculate, for now return 8KBit in bytes (to allow for really big RSA keys)
            return 8 * 1024 / 8;
        }



#if !NET5_0_OR_GREATER
        private static byte[] Ieee1363ToDer(byte[] input)
        {
            // Input is (r, s), each of them exactly half of the array.
            // Output is the DER encoded value of SEQUENCE(INTEGER(r), INTEGER(s)).
            int halfLength = input.Length / 2;

            MemoryStream encoded = new MemoryStream();
            DerSequenceGenerator generator = new DerSequenceGenerator(encoded);
            generator.AddObject(Ieee1363KeyParameterIntegerToDer(input, 0, halfLength)); //add r
            generator.AddObject(Ieee1363KeyParameterIntegerToDer(input, halfLength, halfLength)); //add s
            //generator.Close();

            return encoded.ToArray();
        }

        private static DerInteger Ieee1363KeyParameterIntegerToDer(byte[] paddedInt, int offset, int length)
        {
            int padding = 0;
            while (padding < paddedInt.Length && paddedInt[offset + padding] == 0) padding++;

            if (padding == paddedInt.Length) // all 0, we have the number 0
                new DerInteger(0);

            //false negative, so we need to add 1 more byte in front.
            int extra = paddedInt[offset + padding] >= 0x80 ? 1 : 0;

            byte[] integer = new byte[length - padding + extra];
            Array.Copy(paddedInt, offset + padding, integer, extra, length - padding);

            return new DerInteger(integer);
        }
#endif
    }
}
