using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Egelke.EHealth.Client.Security;
using Xunit;





#if !NETFRAMEWORK
using System.ServiceModel.Federation;
#endif

namespace library_core_tests
{

#if NETFRAMEWORK
    public class GenericXmlSecurityTokenParameters : SecurityTokenParameters
    {
        protected override bool HasAsymmetricKey => true;

        protected override bool SupportsClientAuthentication => true;

        protected override bool SupportsServerAuthentication => false;

        protected override bool SupportsClientWindowsIdentity => false;

        protected override SecurityTokenParameters CloneCore()
        {
            return new GenericXmlSecurityTokenParameters();
        }

        protected override SecurityKeyIdentifierClause CreateKeyIdentifierClause(SecurityToken token, SecurityTokenReferenceStyle referenceStyle)
        {
            GenericXmlSecurityToken gToken = token as GenericXmlSecurityToken;
            switch(referenceStyle)
            {
                case SecurityTokenReferenceStyle.Internal:
                    return gToken.InternalTokenReference;
                case SecurityTokenReferenceStyle.External:
                    return gToken.ExternalTokenReference;
            }
            throw new NotImplementedException();
        }

        protected override void InitializeSecurityTokenRequirement(SecurityTokenRequirement requirement)
        {
            requirement.TokenType = SecurityTokenTypes.X509Certificate; // or a custom URI
            requirement.RequireCryptographicToken = false;
            requirement.Properties["TokenType"] = typeof(GenericXmlSecurityToken);

        }
    }
#endif

    public class ReferenceTest
    {
        public MyX509Certificate2 ec = new MyX509Certificate2("files/ectest.p12", "");
        public MyX509Certificate2 rsa = new MyX509Certificate2("files/rsatest.p12", "");

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

        [SkippableFact]
        public void soap12Wss10Ecdsa()
        {
            //.Net framework does not use the proper methods to obtain the client's certificate key.
            Skip.If(RuntimeInformation.FrameworkDescription.StartsWith(".NET Framework"));

            var binding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            binding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            binding.Security.Message.NegotiateServiceCredential = false;
            binding.Security.Message.EstablishSecurityContext = false;
            binding.Security.Message.AlgorithmSuite = EC384AlgorithmSuite.EC384;

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss10");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = ec;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [SkippableFact]
        public void experiment()
        {
            //.Net Standard doesn't support messge security
            Skip.IfNot(RuntimeInformation.FrameworkDescription.StartsWith(".NET Framework"));

            var binding = new CustomBinding();
            var security = new TransportSecurityBindingElement();
#if NETFRAMEWORK
            security.EndpointSupportingTokenParameters.Endorsing.Add(new GenericXmlSecurityTokenParameters());
#endif
            security.IncludeTimestamp = true;
            security.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;

            binding.Elements.Add(security);
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

            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss10");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new CustomCredentials());
            channelFactory.Credentials.ClientCertificate.Certificate = rsa;

            IEchoService client = channelFactory.CreateChannel();


            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

        [Fact(Skip ="Implementations are very limited")]
        public void federation()
        {
            //var stsEp = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/SingleSignOnService/v1");
            var stsEp = new EndpointAddress("https://localhost:8080/services/sts/soap12");

            var stsBinding = new WSHttpBinding(SecurityMode.TransportWithMessageCredential);
            stsBinding.Security.Message.ClientCredentialType = MessageCredentialType.Certificate;
            stsBinding.Security.Message.NegotiateServiceCredential = false;
            stsBinding.Security.Message.EstablishSecurityContext = false;

            
#if NETFRAMEWORK
            WS2007FederationHttpBinding binding = new WS2007FederationHttpBinding();
            binding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            binding.Security.Message.IssuerAddress = stsEp;
            binding.Security.Message.IssuerBinding = stsBinding;
            //binding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
            binding.Security.Message.IssuedTokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";

            ClaimTypeRequirement ctr = new ClaimTypeRequirement("http://example.org/claim/c1", false);
            binding.Security.Message.ClaimTypeRequirements.Add(ctr);

#else
            var parameters = WSTrustTokenParameters.CreateWSFederationTokenParameters(stsBinding, stsEp);
            parameters.KeyType = SecurityKeyType.AsymmetricKey;
            parameters.TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
            parameters.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            WSFederationHttpBinding binding = new WSFederationHttpBinding(parameters);
#endif
            var ep = new EndpointAddress("https://localhost:8080/services/echo/soap12wss11");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            channelFactory.Credentials.ClientCertificate.Certificate = rsa;

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
        }

    }
}
