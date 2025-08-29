using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using Egelke.EHealth.Client.Security;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client
{
    public class EhBinding : Binding
    {
        public ILogger<CustomSecurity> Logger { get; }

        public bool BypassProxyOnLocal { get; set; }

        public bool UseDefaultWebProxy { get; set; }

        public Uri ProxyAddress { get; set; }

        public EhBinding(ILogger<CustomSecurity> logger = null)
        {
            Logger = logger;
            BypassProxyOnLocal = true;
            UseDefaultWebProxy = true;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection();
            elements.Add(CreateSecurity());
            elements.Add(CreateMessageEncoding());
            elements.Add(CreateTransport());
            return elements.Clone();
        }

        protected BindingElement CreateSecurity()
        {
            return new CustomSecurityBindingElement(logger: Logger)
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10,
                SignParts = SignParts.All
            };
        }

        protected MessageEncodingBindingElement CreateMessageEncoding()
        {
            return new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11
            };
        }

        protected TransportBindingElement CreateTransport()
        {
            return new HttpsTransportBindingElement()
            {
                AuthenticationScheme = System.Net.AuthenticationSchemes.Anonymous,
                BypassProxyOnLocal = BypassProxyOnLocal,
                UseDefaultWebProxy = UseDefaultWebProxy,
                ProxyAddress = ProxyAddress
            };
        }

        public override string Scheme => "https";

        public void ApplyClientCredentials(ChannelFactory channelFactory)
        {
            channelFactory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
            channelFactory.Endpoint.EndpointBehaviors.Add(new EhCredentials());
        }

    }
}
