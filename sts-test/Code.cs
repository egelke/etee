using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Client.Sso.Sts.Service;
using Siemens.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Siemens.EHealth.Client.Sso;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;

namespace Siemens.EHealth.Client.StsTest
{
    [TestClass]
    public class Code
    {
        private static X509Certificate2 selfSignedSession;

        private static Collection<XmlElement> assertedDefault;

        private static Collection<ClaimTypeRequirement> requestedDefault;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            selfSignedSession = CertGenerator.GenerateSelfSigned(TimeSpan.FromMinutes(30));


            IList<XmlElement> claims;
            claims = new List<XmlElement>();
            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:person:ssin\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">79021802145</saml:AttributeValue>" +
                "</saml:Attribute>");
            claims.Add(doc.DocumentElement);
            doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">79021802145</saml:AttributeValue>" +
                "</saml:Attribute>");
            claims.Add(doc.DocumentElement);
            assertedDefault = new Collection<XmlElement>(claims);

            IList<ClaimTypeRequirement> claimReq;
            claimReq = new List<ClaimTypeRequirement>();
            claimReq.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin"));
            requestedDefault = new Collection<ClaimTypeRequirement>(claimReq);
        }

        [TestMethod]
        public void Normal()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            XmlElement assertion = target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);

            Assert.AreEqual("Assertion", assertion.LocalName);
            Assert.AreEqual("urn:oasis:names:tc:SAML:1.0:assertion", assertion.NamespaceURI);
        }
    }
}
