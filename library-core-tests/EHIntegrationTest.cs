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
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.ECDSA;
using Egelke.EHealth.Client.Security;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Client.Sts.Saml11;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Egelke.Eid.Client;
using Microsoft.Extensions.Logging;
using Xunit;

namespace library_core_tests
{

    public class EHIntegrationTest
    {
        public static IEnumerable<object[]> GetCerts()
        {
            List<object[]> certs = new List<object[]>();
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
            var certp12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            certs.Add(new object[] { new MyX509Certificate2(certp12["authentication"]) });
            
            return certs;
        }

        private ILoggerFactory loggerFactory;

        private X509Certificate2 issuer;

        private X509Certificate2 session;

        private EhBinding binding;

        private EndpointAddress samlpEp;
        private EndpointAddress wstEp;

        private String ssin;

        private IList<Claim> assertingClaims;

        private IList<Claim> additionalClaims;

        private IStsClient target;

        private XmlElement assertion;

        public EHIntegrationTest()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            //wstEp = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/SecurityTokenService/v1");
            wstEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            //samlpEp = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            samlpEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/Saml11TokenService/v1");

            //var p12 = new EHealthP12("files/ehealth-01050399864-int.p12", File.ReadAllText("files/ehealth-01050399864-int.p12.pwd"));
            //var p12 = new EHealthP12("files/ehealth-79021802145-acc.p12", File.ReadAllText("files/ehealth-79021802145-acc.p12.pwd"));
            var p12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            session = p12["authentication"];

            //issuer = new X509Certificate2("files/IAMINT.cer");
            issuer = new X509Certificate2("files/IAMACC.cer");

            binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>())
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8888")
            };
        }

        private void Prep(X509Certificate2 user)
        {
            Match match = Regex.Match(user.Subject, @"(SSIN|SERIALNUMBER)=(\d{11})");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            ssin = match.Groups[2].Value;

            assertingClaims = new List<Claim>();
            assertingClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin));
            //assertingClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin));

            additionalClaims = new List<Claim>();
            additionalClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", String.Empty));
        }

        private void Verify() { 
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");
            Assert.Equal("urn:be:fgov:ehealth:sts:1_0", assertion.SelectSingleNode("@Issuer").Value);
            Assert.Equal(ssin, assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin']/s11:AttributeValue/text()", nsMngr).Value);
            
            Assert.True(bool.Parse(assertion.SelectSingleNode("./s11:AttributeStatement/s11:Attribute[@AttributeName='urn:be:fgov:person:ssin:doctor:boolean']/s11:AttributeValue/text()", nsMngr).Value));

            SignedXml signed = new CustomSignedXml(assertion);
            XmlNodeList nodeList = assertion.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");
            signed.LoadXml((XmlElement)nodeList[0]);

            Assert.True(signed.CheckSignature(issuer, true));
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void WsTrustWithExplicitSession(X509Certificate2 cert)
        {
            Prep(cert);
            var client = new WsTrustClient(binding, wstEp, loggerFactory.CreateLogger<WsTrustClient>());
            client.ClientCredentials.ClientCertificate.Certificate = cert;
            //client.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            assertion = client.RequestTicket(session, TimeSpan.FromHours(1), assertingClaims, additionalClaims);
            Verify();

            assertion = client.RenewTicket(session, assertion);
            Verify();
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void WsTrustNoExplicitSession(X509Certificate2 cert)
        {
            Prep(cert);
            var client = new WsTrustClient(binding, wstEp, loggerFactory.CreateLogger<WsTrustClient>());
            client.ClientCredentials.ClientCertificate.Certificate = cert;
            //client.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            assertion = client.RequestTicket(null, TimeSpan.FromHours(1), assertingClaims, additionalClaims);
            Verify();

            assertion = client.RenewTicket(null, assertion);
            Verify();
        }



        [Theory(Skip = "Doesn't support EC cert and that is the only one I currently have")]
        [MemberData(nameof(GetCerts))]
        public void StsSaml11(X509Certificate2 cert)
        {
            Prep(cert);

            var client = new SamlClient("Anonymous", binding, samlpEp);
            client.ClientCredentials.ClientCertificate.Certificate = cert;

            assertion = client.RequestTicket(session, TimeSpan.FromHours(1), assertingClaims, additionalClaims);
            Verify();
        }
    }


}
