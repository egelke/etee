using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
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
            var rsaKey = privateKey as RSA;
            if (rsaKey != null)
            {
#if NET452
                var rsaProviderKey = rsaKey  as RSACryptoServiceProvider;
                return rsaProviderKey.SignHash(hashAlgorithm.Hash, hashOid.Value);
#else
                HashAlgorithmName han;
                switch (hashOid.FriendlyName)
                {
                    case "SHA256":
                        han = HashAlgorithmName.SHA256;
                        break;
                    case "SHA512":
                        han = HashAlgorithmName.SHA512;
                        break;
                    default:
                        throw new InvalidOperationException("Hash algorithm not supported :" + hashOid.FriendlyName);
                }
                return rsaKey.SignHash(hashAlgorithm.Hash, han, RSASignaturePadding.Pkcs1);
#endif
            }

            var dsaKey = privateKey as DSA;
            if (dsaKey != null)
            {
                return dsaKey.CreateSignature(hashAlgorithm.Hash);
            }

            throw new InvalidOperationException("Unsuported key type: " + privateKey.GetType());
        }

        public int Collect(byte[] destination, int offset)
        {
            byte[] signature = Collect();
            signature.CopyTo(destination, offset);
            return signature.Length;
        }
    }
}
