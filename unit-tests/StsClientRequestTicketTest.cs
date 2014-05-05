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
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Claims;
using System.Xml;
using Egelke.EHealth.Client.Sso.Sts.Service;
using Egelke.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using Egelke.EHealth.Client.Sso;
using System.Collections.Generic;
using System.ServiceModel.Security.Tokens;
using System.Collections.ObjectModel;
using System.ServiceModel.Channels;
using Egelke.EHealth.Client.Sso.Sts.WcfAddition;
using System.ServiceModel.Security;
using NUnit.Framework;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    
    
    /// <summary>
    ///This is a test class for StsClientTest and is intended
    ///to contain all StsClientTest Unit Tests
    ///</summary>
    [TestFixture]
    public class StsClientRequestTicketTest
    {
        private static X509Certificate2 selfSignedSession;

        private static Collection<XmlElement> assertedDefault;

        private static Collection<ClaimTypeRequirement> requestedDefault;

        [TestFixtureSetUp]
        public static void MyClassInitialize()
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
        


        /// <summary>
        ///A test for RequestTicket
        ///</summary>
        [Test]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AllNull()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.RequestTicket(null, null, DateTime.MinValue, DateTime.MaxValue, null, null);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void NoClientCert()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }

        [Test]
        [ExpectedException(typeof(InvalidOperationException))]
        public void NoServerCert()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }

        [Test]
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
        [Test]
        [ExpectedException(typeof(ProtocolException))]
        public void InvalidAddressPage()
        {
            StsClient target = new StsClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/sss_1_1/SecureTokenService"));
            target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107");
            target.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");
            target.RequestTicket("Siemens", selfSignedSession, TimeSpan.FromMinutes(10), assertedDefault, requestedDefault);
        }
         */

        
    }
}
