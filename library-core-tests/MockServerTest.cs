using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Egelke.Eid.Client;
using Microsoft.Extensions.Logging;
using Xunit;

namespace library_core_tests
{

    public class MockServiceTest
    {
        public static IEnumerable<object[]> GetCerts()
        {
            List<object[]> certs = new List<object[]>();
            certs.Add(new object[] { new MyX509Certificate2("files/ectest.p12", "") });
            certs.Add(new object[] { new MyX509Certificate2("files/rsatest.p12", "") });
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
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity10)));
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
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity10)));
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
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new CustomClientCredentials());
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void Soap11Wss11(X509Certificate2 cert)
        {
            var binding = new CustomBinding();
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity11)));
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

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap11wss11");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new CustomClientCredentials());
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
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity10)));
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
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity11)));
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
            binding.Elements.Add(new CustomSecurityBindingElement(new CustomSecurity(SecurityVersion.WSSecurity10)) {
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

        [Theory]
        [MemberData(nameof(GetCerts))]
        public void EhealthX509(X509Certificate2 cert)
        {
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());

            var ep = new EndpointAddress("https://localhost:8080/services/echo/eHealth/x509");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = cert;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }
    }

}
