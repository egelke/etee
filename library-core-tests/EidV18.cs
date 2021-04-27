using Egelke.EHealth.Client.Sso.Helper;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

namespace library_core_tests
{

    public class EidV18 : IDisposable
    {

        private byte[] clearMsg;

        X509Certificate2 eid;
        RSA privateRsa;
        RSA publicRsa;
        ECDsa privateEcdsa;
        ECDsa publicEcdsa;

        public EidV18()
        {
            ECDsaConfig.Init();
            clearMsg = System.Text.Encoding.UTF8.GetBytes("Hello world");

            eid = Config.Instance.Certificate;
            privateRsa = eid.GetRSAPrivateKey();
            publicRsa = eid.GetRSAPublicKey();
            privateEcdsa = eid.GetECDsaPrivateKey();
            publicEcdsa = eid.GetECDsaPublicKey();
        }

        [Fact]
        public void Sign()
        {

            byte[] signature;
            if (privateRsa != null)
            {
                signature = privateRsa.SignData(clearMsg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else if (privateEcdsa != null)
            {
                signature = privateEcdsa.SignData(clearMsg, HashAlgorithmName.SHA256);
            }
            else
            {
                signature = null;
            }
            Assert.NotNull(signature);

            if (publicRsa != null)
            {
                Assert.True(publicRsa.VerifyData(clearMsg, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            else if (publicEcdsa != null)
            {
                Assert.True(publicEcdsa.VerifyData(clearMsg, signature, HashAlgorithmName.SHA256));
            }
        }


        [Fact]
        public void SignXml()
        {

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load("test.xml");

            var signedXml = new SignedXml(doc);
            if (privateRsa != null)
            {
                signedXml.SigningKey = privateRsa;
            }
            else
            {
                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"; //required for ECDSA
                signedXml.SigningKey = privateEcdsa;
            }

            Reference reference = new Reference();
            reference.Uri = "#_1";

            var transform = new XmlDsigExcC14NTransform();
            reference.AddTransform(transform);

            signedXml.AddReference(reference);
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(eid));

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();

            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));


            XmlTextWriter xmltw = new XmlTextWriter("testSigned.xml", Encoding.UTF8);
            doc.WriteTo(xmltw);
            xmltw.Close();
        }

        [Fact]
        public void VerifyXml()
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load("testSigned.xml");

            var signedXml = new SignedXml(doc);
            XmlNodeList nodeList = doc.GetElementsByTagName("Signature");
            signedXml.LoadXml((XmlElement)nodeList[0]);

            X509Certificate2 cert = null;
            //very basic implementation, don't use as is.
            IEnumerator certInfoList = signedXml.KeyInfo.GetEnumerator(typeof(KeyInfoX509Data));
            while (certInfoList.MoveNext())
            {
                ArrayList certList = ((KeyInfoX509Data)certInfoList.Current).Certificates;
                cert = (X509Certificate2)certList[0];
            }

            Assert.True(signedXml.CheckSignature(cert.GetECDsaPublicKey()));
        }

        //[Fact]
        public void WcfClient()
        {
            var binding = new BasicHttpBinding(BasicHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.ClientCredentialType = BasicHttpMessageCredentialType.Certificate;
            binding.Security.Message.AlgorithmSuite = new MySecurityAlgorithmSuite();

            EndpointAddress ep = new EndpointAddress("https://localhost/MathService/Ep1");
            ChannelFactory<IEcho> channelFactory = new ChannelFactory<IEcho>(binding, ep);
            //channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);

            IEcho client = channelFactory.CreateChannel();

            client.Ping("boe");
        }

        public void Dispose()
        {
            eid?.Dispose();
            publicRsa?.Dispose();
            privateRsa?.Dispose();
            publicEcdsa?.Dispose();
            privateEcdsa?.Dispose();
        }

    }

    public class MySecurityAlgorithmSuite : SecurityAlgorithmSuite
    {
        public MySecurityAlgorithmSuite() : base() { }

        public override string DefaultCanonicalizationAlgorithm { get { return "http://www.w3.org/2001/10/xml-exc-c14n#"; } }
        public override string DefaultDigestAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#sha256"; } }
        public override string DefaultEncryptionAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#aes128-cbc"; } }
        public override int DefaultEncryptionKeyDerivationLength { get { return 256; } }
        public override string DefaultSymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#kw-aes256"; } }
        public override string DefaultAsymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"; } }
        public override string DefaultSymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"; } }
        public override string DefaultAsymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"; } }
        public override int DefaultSignatureKeyDerivationLength { get { return 192; } }
        public override int DefaultSymmetricKeyLength { get { return 256; } }

#if NETFRAMEWORK
        public override bool IsSymmetricKeyLengthSupported(int length) { return length == 256; }
        public override bool IsAsymmetricKeyLengthSupported(int length) { return length >= 1024 && length <= 4096; }
#else
        public bool IsSymmetricKeyLengthSupported(int length) { return length == 256; }
        public bool IsAsymmetricKeyLengthSupported(int length) { return length >= 1024 && length <= 4096; }
#endif


        public override string ToString()
        {
            return "ECDSA256";
        }
    }


    [ServiceContract()]
    interface IEcho
    {
        [OperationContract()]
        string Ping(string value);
    }
}
