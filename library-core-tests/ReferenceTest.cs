using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Xunit;

#if !NETFRAMEWORK
using System.ServiceModel.Federation;
#endif

namespace library_core_tests
{
    public class ReferenceTest
    {
        public MyX509Certificate2 ec = new MyX509Certificate2("files/eccert.p12", "");
        public MyX509Certificate2 rsa = new MyX509Certificate2("files/rsacert.p12", "");

        [Fact]
        public void soap11Plain()
        {
            var binding = new BasicHttpsBinding();
            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap11");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact]
        public void soap12Plain()
        {
            var binding = new WSHttpBinding(SecurityMode.Transport);
            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact]
        public void soap12Wss10Rsa()
        {
            var binding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.NegotiateServiceCredential = false;
            binding.Security.Message.EstablishSecurityContext = false;

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss10");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = rsa;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }


        [Fact]
        public void federation()
        {
            //var stsEp = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/SingleSignOnService/v1");
            var stsEp = new EndpointAddress("https://localhost:8080/sts/soap11");

            var stsBinding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            stsBinding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            stsBinding.Security.Message.NegotiateServiceCredential = false;
            stsBinding.Security.Message.EstablishSecurityContext = false;
            stsBinding.ProxyAddress = new Uri("http://localhost:8888");
            stsBinding.BypassProxyOnLocal = false;
            stsBinding.UseDefaultWebProxy = false;  

            WSFederationHttpBinding binding;
#if NETFRAMEWORK
            binding = new WSFederationHttpBinding();
            binding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            binding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
            binding.Security.Message.IssuerAddress = stsEp;
            binding.Security.Message.IssuerBinding = stsBinding;
            binding.Security.Message.IssuedTokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";

            ClaimTypeRequirement ctr = new ClaimTypeRequirement("http://example.org/claim/c1", false);
            binding.Security.Message.ClaimTypeRequirements.Add(ctr);

#else
            var parameters = WSTrustTokenParameters.CreateWSFederationTokenParameters(stsBinding, stsEp);
            parameters.KeyType = SecurityKeyType.AsymmetricKey;
            parameters.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
            binding = new WSFederationHttpBinding(parameters);
            binding.ProxyAddress = new Uri("http://localhost:8888");
            binding.BypassProxyOnLocal = false;
            binding.UseDefaultWebProxy = false;
#endif
            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = rsa;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

    }
}
