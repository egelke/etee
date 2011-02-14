/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

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
using Siemens.EHealth.Client.Sso.WA;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Description;

namespace Siemens.EHealth.Client.StsTest
{
    [TestClass]
    public class Examples
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
        public void ConfigViaCode()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.Endpoint.Behaviors.Remove<ClientCredentials>();
            target.Endpoint.Behaviors.Add(new OptClientCredentials());
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            XmlElement assertion = target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);

            Assert.AreEqual("Assertion", assertion.LocalName);
            Assert.AreEqual("urn:oasis:names:tc:SAML:1.0:assertion", assertion.NamespaceURI);
        }

        [TestMethod]
        public void ConfigViaConfig()
        {
            StsClient target = new StsClient("SSIN=79021802145");
            XmlElement assertion = target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);

            Assert.AreEqual("Assertion", assertion.LocalName);
            Assert.AreEqual("urn:oasis:names:tc:SAML:1.0:assertion", assertion.NamespaceURI);
        }
    }
}
