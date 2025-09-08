using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Pki.ECDSA;
using Egelke.Eid.Client;
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{

    public class ECDSATest
    {
        public static IEnumerable<object[]> GetSoftCerts()
        {
            yield return new object[] { @"files/eccert.p12", "Test_001" };
            yield return new object[] { @"files/rsacert.p12", "Test_001" };
        }


        private byte[] clearMsg;

        public ECDSATest()
        {
            ECDSAConfig.Init();
            clearMsg = System.Text.Encoding.UTF8.GetBytes("Hello world");
        }


        [Theory]
        [MemberData(nameof(GetSoftCerts))]
        public void Sign(string file, string pwd)
        {
            SignInternal(new X509Certificate2(file, pwd));
        }

        private void SignInternal(X509Certificate2 cert)
        {
            var privateRsa = cert.GetRSAPrivateKey();
            var privateEcdsa = cert.GetECDsaPrivateKey();
            var publicRsa = cert.GetRSAPublicKey();
            var publicEcdsa = cert.GetECDsaPublicKey();

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


        [Theory]
        [MemberData(nameof(GetSoftCerts))]
        public void SignXml(String file, String pwd)
        {
            SignXmlInternal(new X509Certificate2(file, pwd));
        }

        private void SignXmlInternal(X509Certificate2 cert)
        {
            var privateRsa = cert.GetRSAPrivateKey();
            var privateEcdsa = cert.GetECDsaPrivateKey();

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(@"files\test.xml");

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
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));

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
            doc.Load(@"files\testSigned.xml");

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

            var publicRsa = cert.GetRSAPublicKey();
            var publicEcdsa = cert.GetECDsaPublicKey();
            if (publicRsa != null)
            {
                Assert.True(signedXml.CheckSignature());
            }
            else if (publicEcdsa != null)
            {
                Assert.True(signedXml.CheckSignature(publicEcdsa));
            }
            else
            {
                Assert.True(false);
            }
        }

        [SkippableFact]
        public void LiveEID()
        {
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                var target = (EidCard)readers.ListCards().Where(c => c is EidCard).FirstOrDefault();
                Skip.If(target == null);
                //Assert.True(target != null, "No eid inserted, please insert (test) eid");
                target.Open();

                store.Open(OpenFlags.ReadOnly);
                X509Certificate2 cert = store.Certificates.Find(X509FindType.FindByThumbprint, target.AuthCert.Thumbprint, false)[0];

                SignInternal(cert);
                SignXmlInternal(cert);
            }
        }
    }


}
