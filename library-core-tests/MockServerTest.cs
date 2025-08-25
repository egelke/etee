using Egelke.EHealth.Client.Pki;
using Egelke.Eid.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Security;
using Egelke.EHealth.Client.Sts.Saml11;
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
using Egelke.EHealth.Client.Pki.ECDSA;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace library_core_tests
{

    public class MockServiceTest
    {
        public static IEnumerable<object[]> GetCerts()
        {
            List<object[]> certs = new List<object[]>();
            //using (var readers = new Readers(ReaderScope.User))
            //using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            //{
            //    store.Open(OpenFlags.ReadOnly);
            //    certs = readers.ListCards()
            //        .OfType<EidCard>()
            //        .Select(c =>
            //        {
            //            c.Open();
            //            String thumbprint = c.AuthCert.Thumbprint;
            //            c.Close();
            //            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];
            //        })
            //        .Select(c => new object[] { new MyX509Certificate2(c) })
            //        .ToList();
            //}
            //certs.Add(new object[] { new MyX509Certificate2("files/eccert.p12", "") });
            var certp12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            certs.Add(new object[] { new MyX509Certificate2(certp12["authentication"]) });
            return certs;
        }

        private ILoggerFactory loggerFactory;

        public MockServiceTest()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
            using (var localhost = new X509Certificate2("files/localhost.cer"))
            using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
                var test = localhost.Thumbprint;
                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, localhost.Thumbprint, false);
                if (found.Count == 0)
                {
                    throw new InvalidOperationException("localhost cert not trusted");
                    //store.Add(localhost);
                }
            }

            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
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

        [Theory(Skip="Mock implementation not ready")]
        [MemberData(nameof(GetCerts))]
        public void WsTrust(X509Certificate2 cert)
        {
            var msgLogger = loggerFactory.CreateLogger<LoggingMessageInspector>();

            var binding = new StsBinding();
            var client = new WsTrustClient(binding, new EndpointAddress("https://localhost:8080/services/sts/soap12"));
            //var client = new WsTrustClient(binding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1"));
            client.ClientCredentials.ClientCertificate.Certificate = cert;
            client.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(msgLogger));

            var assertingClaims = new List<Claim>();
            assertingClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", "79021802145"));
            var additionalClaims = new List<Claim>();


            var response = client.RequestTicket(cert, TimeSpan.FromHours(1), assertingClaims, additionalClaims);
            
        }
    }

}
