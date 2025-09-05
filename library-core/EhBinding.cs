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

        public CustomSecurity Security { get; } = new CustomSecurity();

        public bool BypassProxyOnLocal { get; set; } = true;

        public bool UseDefaultWebProxy { get; set; } = true;

        public Uri ProxyAddress { get; set; }

        public EhBinding(ILogger<CustomSecurity> logger = null)
        {
            Logger = logger;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection() {
                CreateSecurity(),
                CreateMessageEncoding(),
                CreateTransport()
            };
            return elements;
        }

        protected BindingElement CreateSecurity()
        {
            return new CustomSecurityBindingElement(Security, Logger)
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity11,
                SignParts = SignParts.All
            };
        }

        protected MessageEncodingBindingElement CreateMessageEncoding()
        {
            return new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11,
                
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
    }
}
