using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Sso.Sts;
using Egelke.Eid.Client;
using Egelke.Wcf.Client.Helper;
using Egelke.Wcf.Client.Security;
using Egelke.Wcf.Client.Sts.Saml11;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Xunit;

namespace library_core_tests
{

    public class EHIntegrationTest
    {
        public static IEnumerable<object[]> GetCerts()
        {
            List<object[]> certs;
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                certs = readers.ListCards()
                    .OfType<EidCard>()
                    .Select(c =>
                    {
                        c.Open();
                        String thumbprint = c.AuthCert.Thumbprint;
                        c.Close();
                        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];
                    })
                    .Select(c => new object[] { new MyX509Certificate2(c) })
                    .ToList();
            }
            return certs;
        }

        public EHIntegrationTest()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void StsSaml11(X509Certificate2 cert)
        {
            var doc = new XmlDocument();
            Match match = Regex.Match(cert.Subject, @"SERIALNUMBER=(\d{11}),");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            string ssin = match.Groups[1].Value;

            var claims = new List<XmlElement>();
            var attr = doc.CreateElement("Attribute", "urn:oasis:names:tc:SAML:1.0:assertion");
            attr.SetAttribute("AttributeNamespace", "urn:be:fgov:identification-namespace");
            attr.SetAttribute("AttributeName", "urn:be:fgov:person:ssin");
            var attrVal = doc.CreateElement("AttributeValue", "urn:oasis:names:tc:SAML:1.0:assertion");
            attrVal.SetAttribute("type", "http://www.w3.org/2001/XMLSchema-instance", "xs:string");
            attrVal.SetAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");
            var attrValText = doc.CreateTextNode(ssin);
            attrVal.AppendChild(attrValText);
            attr.AppendChild(attrVal);
            claims.Add(attr);

            attr = (XmlElement)attr.CloneNode(true);
            attr.SetAttribute("AttributeNamespace", "urn:be:fgov:identification-namespace");
            attr.SetAttribute("AttributeName", "urn:be:fgov:ehealth:1.0:certificateholder:person:ssin");
            attrVal = (XmlElement)attr.FirstChild;
            attrVal.SetAttribute("type", "http://www.w3.org/2001/XMLSchema-instance", "xs:string");
            attrValText = (XmlText)attrVal.FirstChild;
            attrValText.Data = ssin;
            claims.Add(attr);

            var session = new EHealthP12("files/ehealth-01050399864-int.p12", File.ReadAllText("files/ehealth-01050399864-int.p12.pwd"));
            //var session = new EHealthP12("files/ehealth-79021802145-acc.p12", File.ReadAllText("files/ehealth-79021802145-acc.p12.pwd"));
            var binding = new StsBinding()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            };

            var ep = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            //var ep = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            StsClient target = new StsClient(binding, ep);
            target.ClientCredentials.ClientCertificate.Certificate = cert;
            XmlElement assertion = target.RequestTicket("Anonymous", session["authentication"], TimeSpan.FromHours(1), claims, claims);

            XmlNamespaceManager nsMngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");
            Assert.Equal("urn:be:fgov:ehealth:sts:1_0", assertion.SelectSingleNode("@Issuer").Value);
            Assert.Equal(ssin, assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin']/s11:AttributeValue/text()", nsMngr).Value);
        }
    }


}
