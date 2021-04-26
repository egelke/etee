using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Helper
{
    public abstract class ECDsaSignatureDescription : SignatureDescription
    {
        public ECDsaSignatureDescription(String digestAlg)
        {
            var type = Type.GetType(typeof(System.Security.Cryptography.ECDsaCng).AssemblyQualifiedName); //TODO:MAKE Platform independant.
            KeyAlgorithm = typeof(System.Security.Cryptography.ECDsaCng).AssemblyQualifiedName;
            DigestAlgorithm = digestAlg;
            FormatterAlgorithm = nameof(ECDSASignatureFormatter);
            DeformatterAlgorithm = nameof(ECDSASignatureDeformatter);
        }
    }

    public class ECDsaSha1SignatureDescription : ECDsaSignatureDescription
    {
        public ECDsaSha1SignatureDescription()
           : base("SHA1")
        {

        }
    }

    public class ECDsaSha256SignatureDescription : ECDsaSignatureDescription
    {
        public ECDsaSha256SignatureDescription()
           : base("SHA256")
        {

        }
    }
}
