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

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Client.Sso.Sts.Service;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Claims;
using Siemens.EHealth.Client.Sso;
using System.Xml;
using System.IO;
using System.Xml.Schema;
using System.Security.Cryptography.Xml;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class RequestTest
    {
        private static X509Certificate2 selfSignedSession;

        private static X509Certificate2 eidCertificate;

        private static Collection<XmlElement> assertedDefault;

        private static Collection<ClaimTypeRequirement> requestedDefault;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            selfSignedSession = CertGenerator.GenerateSelfSigned(TimeSpan.FromMinutes(20));

            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            try
            {
                eidCertificate = store.Certificates.Find(X509FindType.FindByThumbprint, "c0f554147928c3722670a47be2f92a9089add107", false)[0];
            }
            finally
            {
                store.Close();
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
            requestedDefault = new Collection<ClaimTypeRequirement>(claimReq);
        }

        [TestMethod]
        public void Write()
        {
            //create request
            Request request = new Request("Siemens", eidCertificate, selfSignedSession, DateTime.UtcNow, DateTime.UtcNow.AddDays(1.0), assertedDefault, requestedDefault);

            //Save request
            XmlWriter writer = XmlWriter.Create("out.xml");
            request.Save(writer);
        }

        /*
        [TestMethod]
        public void ValidateSignature()
        {
            //create request
            Request request = new Request("Siemens", eidCertificate, selfSignedSession, DateTime.UtcNow, DateTime.UtcNow.AddDays(1.0), assertedDefault, requestedDefault);

            //Save request
            MemoryStream buffer = new MemoryStream();
            XmlWriter writer = XmlWriter.Create(buffer);
            request.Save(writer);

            //Validate saved request
            buffer.Position = 0;
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(buffer);

            SignedXml signed = new SignedXml(doc);
            Assert.IsTrue(signed.CheckSignature());
        }*/

        [TestMethod]
        public void ValideWithXsd()
        {
            //create request
            Request request = new Request("Siemens", eidCertificate, selfSignedSession, DateTime.UtcNow, DateTime.UtcNow.AddDays(1.0), assertedDefault, requestedDefault);

            //Save request
            MemoryStream buffer = new MemoryStream();
            XmlWriter writer = XmlWriter.Create(buffer);
            request.Save(writer);

            //Validate saved request
            XmlSchemaSet schemas = new XmlSchemaSet();
            schemas.Add("urn:oasis:names:tc:SAML:1.0:protocol", "saml-protocol.xsd");
            schemas.Add("urn:oasis:names:tc:SAML:1.0:assertion", "saml-assertion.xsd");
            schemas.Add("http://www.w3.org/2000/09/xmldsig#", "xmldsig.xsd");

            XmlReaderSettings settings = new XmlReaderSettings();
            settings.Schemas = schemas;
            settings.ValidationType = ValidationType.Schema;
            settings.ValidationEventHandler += new ValidationEventHandler(settings_ValidationEventHandler);

            buffer.Position = 0;
            XmlReader reader = XmlReader.Create(buffer, settings);
            while (reader.Read());
        }

        void settings_ValidationEventHandler(object sender, ValidationEventArgs e)
        {
            throw e.Exception;
        }
    }
}
