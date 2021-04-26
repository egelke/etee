using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Helper
{
    public class ECDsaConfig
    {
        static ECDsaConfig()
        {
            CryptoConfig.AddAlgorithm(typeof(ECDSASignatureFormatter), nameof(ECDSASignatureFormatter));
            CryptoConfig.AddAlgorithm(typeof(ECDSASignatureDeformatter), nameof(ECDSASignatureDeformatter));
            CryptoConfig.AddAlgorithm(typeof(ECDsaSha1SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
            CryptoConfig.AddAlgorithm(typeof(ECDsaSha256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        }

        public static void Init()
        {
            //invoke the static constuctor.
        }

    }
}
