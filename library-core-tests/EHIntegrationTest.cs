using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.ECDSA;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Client.Sts.Saml11;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Egelke.Eid.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
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
        public void WsTrust(X509Certificate2 cert)
        {
            Match match = Regex.Match(cert.Subject, @"SERIALNUMBER=(\d{11}),");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            string ssin = match.Groups[1].Value;

            var claims = new List<Claim>();
            claims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin));
            claims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin));

            var designators = new List<Claim>();
            designators.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", String.Empty));

            var session = new EHealthP12("files/ehealth-01050399864-int.p12", File.ReadAllText("files/ehealth-01050399864-int.p12.pwd"));
            //var session = new EHealthP12("files/ehealth-79021802145-acc.p12", File.ReadAllText("files/ehealth-79021802145-acc.p12.pwd"));
            var binding = new StsBinding()
            {
                BypassProxyOnLocal = false,
                UseDefaultWebProxy = false,
                ProxyAddress = new Uri("http://localhost:8080")
            };

            var ep = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/SecurityTokenService/v1");
            //var ep = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");
            var target = new WsTrustClient(binding, ep);
            target.ClientCredentials.ClientCertificate.Certificate = cert;
            var stsClient = (IStsClient)target;
            XmlElement assertion = stsClient.RequestTicket(session["authentication"], TimeSpan.FromHours(1), claims, designators);

            XmlNamespaceManager nsMngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");
            Assert.Equal("urn:be:fgov:ehealth:sts:1_0", assertion.SelectSingleNode("@Issuer").Value);
            Assert.Equal(ssin, assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin']/s11:AttributeValue/text()", nsMngr).Value);
            bool doctor;
            Assert.True(bool.TryParse(assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin:doctor:boolean']/s11:AttributeValue/text()", nsMngr).Value, out doctor));

            SignedXml signed = new SignedSaml11(assertion);
            XmlNodeList nodeList = assertion.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            signed.LoadXml((XmlElement)nodeList[0]);

            //Assert.True(signed.CheckSignature(new X509Certificate2("files/IAMACC.cer"), true));
            Assert.True(signed.CheckSignature(new X509Certificate2("files/IAMINT.cer"), true));
        }



        [Theory]
        [MemberData(nameof(GetCerts))]
        public void StsSaml11(X509Certificate2 cert)
        {
            var doc = new XmlDocument();
            Match match = Regex.Match(cert.Subject, @"SERIALNUMBER=(\d{11}),");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            string ssin = match.Groups[1].Value;

            var claims = new List<Claim>();
            claims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin));
            claims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin));

            var designators = new List<Claim>();
            designators.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", String.Empty));

            var session = new EHealthP12("files/ehealth-01050399864-int.p12", File.ReadAllText("files/ehealth-01050399864-int.p12.pwd"));
            //var session = new EHealthP12("files/ehealth-79021802145-acc.p12", File.ReadAllText("files/ehealth-79021802145-acc.p12.pwd"));
            var binding = new StsBinding()
            {
                BypassProxyOnLocal = false,
                UseDefaultWebProxy = false,
                ProxyAddress = new Uri("http://localhost:8080")
            };

            var ep = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            //var ep = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            var target = new SamlClient("Anonymous", binding, ep);
            target.ClientCredentials.ClientCertificate.Certificate = cert;
            var stsClient = (IStsClient)target;
            XmlElement assertion = stsClient.RequestTicket(session["authentication"], TimeSpan.FromHours(1), claims, designators);

            XmlNamespaceManager nsMngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");
            Assert.Equal("urn:be:fgov:ehealth:sts:1_0", assertion.SelectSingleNode("@Issuer").Value);
            Assert.Equal(ssin, assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin']/s11:AttributeValue/text()", nsMngr).Value);
            Assert.Equal(ssin, assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:ehealth:1.0:certificateholder:person:ssin']/s11:AttributeValue/text()", nsMngr).Value);
            bool doctor;
            Assert.True(bool.TryParse(assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin:doctor:boolean']/s11:AttributeValue/text()", nsMngr).Value, out doctor));

            SignedXml signed = new SignedSaml11(assertion);
            XmlNodeList nodeList = assertion.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            signed.LoadXml((XmlElement)nodeList[0]);

            //Assert.True(signed.CheckSignature(new X509Certificate2("files/IAMACC.cer"), true));
            Assert.True(signed.CheckSignature(new X509Certificate2("files/IAMINT.cer"), true));
        }
    }


}
