using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Pki.ECDSA;

namespace Egelke.EHealth.Client.Security
{
    public class EC384AlgorithmSuite : SecurityAlgorithmSuite
    {

        public static readonly EC384AlgorithmSuite EC384 = new EC384AlgorithmSuite();

        public EC384AlgorithmSuite() : base() {
            ECDSAConfig.Init();
        }

        public override string DefaultCanonicalizationAlgorithm { get { return "http://www.w3.org/2001/10/xml-exc-c14n#"; } }
        public override string DefaultDigestAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#sha256"; } }
        public override string DefaultEncryptionAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#aes256-cbc"; } }
        public override int DefaultEncryptionKeyDerivationLength { get { return 256; } }
        public override string DefaultSymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#kw-aes256"; } }
        public override string DefaultAsymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"; } }
        public override string DefaultSymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"; } }
        public override string DefaultAsymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"; } }
        public override int DefaultSignatureKeyDerivationLength { get { return 192; } }
        public override int DefaultSymmetricKeyLength { get { return 256; } }
        public override bool IsSymmetricKeyLengthSupported(int length) { return length == 256; }
        public override bool IsAsymmetricKeyLengthSupported(int length) { return length >= 1024 && length <= 4096; }

        public override string ToString()
        {
            return "EC384";
        }
    }
}
