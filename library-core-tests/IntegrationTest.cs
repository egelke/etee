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
    public class MyX509Certificate2 : X509Certificate2
    {
        public MyX509Certificate2(X509Certificate2 cert) : base(cert)
        {

        }

        public MyX509Certificate2(String file, String pwd) : base(file, pwd)
        {

        }

        public override string ToString()
        {
            return this.GetNameInfo(X509NameType.SimpleName, false);
        }

    }

    public class IntegrationTest
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
            certs.Add(new object[] { new MyX509Certificate2("eccert.p12", "Test_001") });
            return certs;
        }

        public IntegrationTest()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
            using (var localhost = new X509Certificate2("localhost.cer"))
            using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, localhost.Thumbprint, false);
                if (found.Count == 0)
                {
                    throw new InvalidOperationException("localhost cert not trusted");
                    //store.Add(localhost);
                }
            }

        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap11Wss10Failed(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10
            });
            binding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11
            });
            binding.Elements.Add(new HttpsTransportBindingElement()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            });

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap11");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            Assert.Throws<ProtocolException>(() => client.Echo("boe"));
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap11Wss10(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10
            });
            binding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11
            });
            binding.Elements.Add(new HttpsTransportBindingElement()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            });

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap11wss10");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap12Wss10(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10
            });
            binding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap12WSAddressing10
            });
            binding.Elements.Add(new HttpsTransportBindingElement()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            });

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss10");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap12Wss11(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity11
            });
            binding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap12WSAddressing10
            });
            binding.Elements.Add(new HttpsTransportBindingElement()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            });


            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss11");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap11Wss10SignAll(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10,
                SignParts = SignParts.All
            });
            binding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11
            });
            binding.Elements.Add(new HttpsTransportBindingElement()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            });

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap11wss10all");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }



        [Fact]
        public void EhealthStsSaml11()
        {
            X509Certificate2 cert;
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                cert = readers.ListCards()
                    .OfType<EidCard>()
                    .Select(c =>
                    {
                        c.Open();
                        String thumbprint = c.AuthCert.Thumbprint;
                        c.Close();
                        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];
                    })
                    .FirstOrDefault();
            }

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

            var session = new EHealthP12("ehealth-01050399864-int.p12", File.ReadAllText("ehealth-01050399864-int.p12.pwd"));
            //var session = new EHealthP12("ehealth-79021802145-acc.p12", File.ReadAllText("ehealth-79021802145-acc.p12.pwd"));
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

    [ServiceContract(Namespace = "urn:test", Name = "EchoPort")]
    interface IEchoService
    {
        [OperationContract(Action = "urn:test:echo:ping", ReplyAction = "*")]
        [return: MessageParameter(Name = "pong")]
        string Echo(string ping);
    }
}
