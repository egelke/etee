using Egelke.Wcf.Client;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using Xunit;

namespace library_core_tests
{
    public class IntegrationTest
    {
        [Fact]
        public void WcfClient()
        {
            /*
            var binding = new BasicHttpBinding(BasicHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.ClientCredentialType = BasicHttpMessageCredentialType.Certificate;
            binding.BypassProxyOnLocal = false;
            binding.UseDefaultWebProxy = false;
            binding.ProxyAddress = new Uri("http://localhost:8866");
            */

            var binding = new CustomBinding();
            //var security = SecurityBindingElement.CreateUserNameOverTransportBindingElement();
            //security.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;
            var security = new CustomSecurityBindingElement();
            security.MessageSecurityVersion = SecurityVersion.WSSecurity10;
            binding.Elements.Add(security);
            var encoding = new TextMessageEncodingBindingElement();
            encoding.MessageVersion = MessageVersion.Soap11;
            binding.Elements.Add(encoding);
            var transport = new HttpsTransportBindingElement();
            transport.BypassProxyOnLocal = false;
            transport.UseDefaultWebProxy = false;
            transport.ProxyAddress = new Uri("http://localhost:8866");
            binding.Elements.Add(transport);

            EndpointAddress ep = new EndpointAddress("https://localhost:44373/Echo/service.svc");
            ChannelFactory<IEchoService> channelFactory = new ChannelFactory<IEchoService>(binding, ep);
            if (Config.Instance.Thumbprint != null)
                channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
            else
                channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;
            channelFactory.Credentials.UserName.UserName = "bryan";
            channelFactory.Credentials.UserName.Password = "bryan";

            IEchoService client = channelFactory.CreateChannel();

            String pong = client.Echo("boe");
            Assert.Equal("boe", pong);
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
