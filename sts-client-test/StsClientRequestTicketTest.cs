/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Claims;
using System.Xml;
using Siemens.EHealth.Client.Sso.Sts.Service;
using Siemens.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using Siemens.EHealth.Client.Sso;
using System.Collections.Generic;
using System.ServiceModel.Security.Tokens;
using System.Collections.ObjectModel;
using System.ServiceModel.Channels;
using Siemens.EHealth.Client.Sso.Sts.WcfAddition;
using System.ServiceModel.Security;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    
    
    /// <summary>
    ///This is a test class for StsClientTest and is intended
    ///to contain all StsClientTest Unit Tests
    ///</summary>
    [TestClass()]
    public class StsClientRequestTicketTest
    {
        private static X509Certificate2 selfSignedSession;

        private static Collection<XmlElement> assertedDefault;

        private static Collection<ClaimTypeRequirement> requestedDefault;

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            selfSignedSession = CertGenerator.GenerateSelfSigned(TimeSpan.FromMinutes(20));

            
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
        
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        /// <summary>
        ///A test for RequestTicket
        ///</summary>
        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AllNull()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.RequestTicket(null, null, DateTime.MinValue, DateTime.MaxValue, null, null);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void NoClientCert()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void NoServerCert()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }

        [TestMethod]
        [ExpectedException(typeof(EndpointNotFoundException))]
        public void InvalidAddressHttp404()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService2"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }

        //Not clear what the error should be.
        /*
        [TestMethod]
        [ExpectedException(typeof(ProtocolException))]
        public void InvalidAddressPage()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sss_1_1/SecureTokenService"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }
         */

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
