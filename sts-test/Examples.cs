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
using Egelke.EHealth.Client.Sso.Sts.Service;
using Egelke.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Egelke.EHealth.Client.Sso;
using Egelke.EHealth.Client.Sso.WA;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Description;
using System.Security.Cryptography.Xml;

namespace Siemens.EHealth.Client.StsTest
{
    [TestClass]
    public class Examples
    {
        private static X509Certificate2 session;

        private static X509Certificate2 auth;

        private static X509Certificate2 ehSsl;

        private static Collection<XmlElement> assertedDefault;

        private static Collection<ClaimTypeRequirement> requestedDefault;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            ehSsl = new X509Certificate2("ehealthfgovbe.crt");
            
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection fcollection = my.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Certificate Select", "Select a session certificate (cancel to generate a self signed)", X509SelectionFlag.SingleSelection);
                if (scollection.Count == 0)
                {
                    session = CertGenerator.GenerateSelfSigned(TimeSpan.FromMinutes(120));
                }
                else
                {
                    session = scollection[0];
                }
                X509Certificate2Collection acollection = X509Certificate2UI.SelectFromCollection(fcollection, "Certificate Select", "Select a authentication certificate (e.g. eID)", X509SelectionFlag.SingleSelection);
                auth = acollection[0];
            }
            finally
            {
                my.Close();
            }



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
            claimReq.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
            //claimReq.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean"));
            requestedDefault = new Collection<ClaimTypeRequirement>(claimReq);
        }

        [TestMethod]
        public void ConfigViaCode()
        {
            StsClient target = new StsClient(
                new StsBinding(), 
                new EndpointAddress(
                    new Uri("https://services-acpt.ehealth.fgov.be/IAM/SingleSignOnService/v1")
                    //,EndpointIdentity.CreateDnsIdentity("*.int.pub.ehealth.fgov.be")
                    )
                );
            target.Endpoint.Behaviors.Remove<ClientCredentials>();
            target.Endpoint.Behaviors.Add(new OptClientCredentials());
            //target.ClientCredentials.ServiceCertificate.DefaultCertificate = ehSsl; //not really used, but better then the workaround
            target.ClientCredentials.ClientCertificate.Certificate = auth;
            XmlElement assertion = target.RequestTicket("Anonymous", session, TimeSpan.FromHours(1), assertedDefault, requestedDefault);

            Assert.AreEqual("Assertion", assertion.LocalName);
            Assert.AreEqual("urn:oasis:names:tc:SAML:1.0:assertion", assertion.NamespaceURI);
        }

        [TestMethod]
        public void ConfigViaConfig()
        {
            StsClient target = new StsClient("SSIN=79021802145");
            XmlElement assertion = target.RequestTicket("Egelke", session, TimeSpan.FromHours(12), assertedDefault, requestedDefault);
            
            XmlDocument doc = new XmlDocument();
            doc.ImportNode(assertion, true);
            doc.AppendChild(assertion);
            doc.Save(@"D:\tmp\tst.xml");

            Assert.AreEqual("Assertion", assertion.LocalName);
            Assert.AreEqual("urn:oasis:names:tc:SAML:1.0:assertion", assertion.NamespaceURI);

            
        }

    }
}
