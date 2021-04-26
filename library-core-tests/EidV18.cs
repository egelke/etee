using Egelke.EHealth.Client.Sso.Helper;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

namespace library_core_tests
{

    public class EidV18
    {

        private byte[] clearMsg;


        public EidV18()
        {
            ECDsaConfig.Init();
            clearMsg = System.Text.Encoding.UTF8.GetBytes("Hello world");
        }

        [Fact]
        public void Sign()
        {
            X509Certificate2 eid = Config.Instance.Certificate;
            using (RSA privateRsa = eid.GetRSAPrivateKey())
            using (RSA publicRsa = eid.GetRSAPublicKey())
            using (ECDsa privateEcdsa = eid.GetECDsaPrivateKey())
            using(ECDsa publicEcdsa = eid.GetECDsaPublicKey()) 
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
            GC.Collect(); //without it you can't use the key objects
        }


        [Fact]
        public void SignXml()
        {
            X509Certificate2 eid = Config.Instance.Certificate;
            using (RSA privateRsa = eid.GetRSAPrivateKey())
            using (ECDsa privateEcdsa = eid.GetECDsaPrivateKey())
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
            GC.Collect(); //without it you can't use the key objects
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
                ArrayList certList = ((KeyInfoX509Data) certInfoList.Current).Certificates;
                cert = (X509Certificate2)certList[0];
            }

            Assert.True(signedXml.CheckSignature(cert.GetECDsaPublicKey()));
        }

    }
}
