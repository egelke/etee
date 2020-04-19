using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinStreamCalculator : IStreamCalculator
    {
        private readonly Oid hashOid;

        private readonly HashAlgorithm hashAlgorithm;

        private readonly AsymmetricAlgorithm privateKey;

        public WinStreamCalculator(Oid hashOid, HashAlgorithm hashAlgorithm, AsymmetricAlgorithm privateKey)
        {
            this.hashOid = hashOid;
            this.hashAlgorithm = hashAlgorithm;
            this.privateKey = privateKey;
        }

        public Stream Stream => new HashAlgorithmProxy(hashAlgorithm);

        public object GetResult()
        {
            return new WinSignatureResult(hashOid, hashAlgorithm, privateKey);
        }
    }
}
