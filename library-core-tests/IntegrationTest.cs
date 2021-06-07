using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Sso.Sts;
using Egelke.Wcf.Client;
using Egelke.Wcf.Client.Security;
using Egelke.Wcf.Client.Sts.Saml11;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsTrust;
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Federation;
using System.ServiceModel.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Xunit;

namespace library_core_tests
{
    public class IntegrationTest
    {
        [Fact]
        public void Soap11Wss10()
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

            //var ep = new EndpointAddress("https://localhost:44373/Echo/service.svc/soap11wss10");
            var ep = new EndpointAddress("https://localhost:8080/services/Echo");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            if (Config.Instance.Thumbprint != null)
                channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact]
        public void Soap12Wss10()
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

            //var ep = new EndpointAddress("https://localhost:44373/Echo/service.svc/soap11wss10");
            var ep = new EndpointAddress("https://localhost:8080/services/Echo12");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            if (Config.Instance.Thumbprint != null)
                channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact]
        public void Soap12Wss11()
        {
            /*
            var binding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential, false);
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            */

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


            //var ep = new EndpointAddress("https://localhost:44373/Echo/service.svc/soap11wss10");
            var ep = new EndpointAddress("https://localhost:8080/services/Echo12");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            if (Config.Instance.Thumbprint != null)
                channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact]
        public void Soap11Wss10SignAll()
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

            //var ep = new EndpointAddress("https://localhost:44373/Echo/service.svc/soap11wss10");
            var ep = new EndpointAddress("https://localhost:8080/services/Echo");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            if (Config.Instance.Thumbprint != null)
                channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }



        [Fact]
        public void EhealthStsSaml11()
        {
            var doc = new XmlDocument();
            X509Certificate2 cert = Config.Instance.Certificate;
            Match match = Regex.Match(cert.Subject, @"SERIALNUMBER=(\d{11}),");
            if (!match.Success) throw new InvalidProgramException("need an ssin in the cert subject");
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

            var session = new EHealthP12("ehealth-01050399864-int.p12", File.ReadAllText("ehealth-01050399864-int.pwd"));
            //var session = new EHealthP12("ehealth-79021802145-acc.p12", File.ReadAllText("ehealth-79021802145-acc.pwd"));
            var binding = new StsBinding()
            {
                //BypassProxyOnLocal = false,
                //UseDefaultWebProxy = false,
                //ProxyAddress = new Uri("http://localhost:8866")
            };

            var ep = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            //var ep = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/Saml11TokenService/v1");
            StsClient target = new StsClient(binding, ep);
            if (Config.Instance.Thumbprint != null)
                target.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                target.ClientCredentials.ClientCertificate.Certificate = Config.Instance.Certificate;
            XmlElement assertion = target.RequestTicket("Anonymous", session["authentication"], TimeSpan.FromHours(1), claims, claims);
        }

        [Fact]
        public void EhealthStsWsTrust()
        {
            var issuerBinding = new StsBinding();
            issuerBinding.BypassProxyOnLocal = false;
            issuerBinding.UseDefaultWebProxy = false;
            issuerBinding.ProxyAddress = new Uri("http://localhost:8866");

            var endpointAddress = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            using (var memStream = new MemoryStream())
            {
                var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
                {
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
                    Claims = new Claims("http://schemas.xmlsoap.org/ws/2006/12/authorization/authclaims", new List<ClaimType>
                    {
                        new ClaimType()
                        {
                            Uri = "urn:be:fgov:person:ssin",
                            Value = "79021802145"
                        }
                    })
                };
                var serializer = new WsTrustSerializer();

                using (var writer = XmlDictionaryWriter.CreateTextWriter(memStream, Encoding.UTF8, false))
                {
                    serializer.WriteRequest(writer, WsTrustVersion.Trust13, request);
                }

                memStream.Position = 0;
                var reader = XmlDictionaryReader.CreateTextReader(memStream, XmlDictionaryReaderQuotas.Max);

                var requestMessage = Message.CreateMessage(MessageVersion.Soap11, WsTrustActions.Trust13.IssueRequest, reader);

                ChannelFactory<IRequestChannel> channelFactory = new ChannelFactory<IRequestChannel>(issuerBinding, endpointAddress);
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;
                IRequestChannel channel = channelFactory.CreateChannel();

                Message reply = channel.Request(requestMessage);
            }
        }

            [Fact]
        public void EhealthGenIns()
        {

            var issuerBinding = new StsBinding();
            //issuerBinding.Security.Message.ClientCredentialType = BasicHttpMessageCredentialType.Certificate;
            //issuerBinding.Security.Message.EstablishSecurityContext = false;
            issuerBinding.BypassProxyOnLocal = false;
            issuerBinding.UseDefaultWebProxy = false;
            issuerBinding.ProxyAddress = new Uri("http://localhost:8866");

            var endpointAddress = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            /*
            var tokenParameters = WSTrustTokenParameters.CreateWSFederationTokenParameters(issuerBinding, endpointAddress);

            
            var binding = new System.ServiceModel.Federation.WSFederationHttpBinding(tokenParameters);

            var ep = new EndpointAddress("https://services-acpt.ehealth.fgov.be/GenericInsurability/v1");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;
            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
            */
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
