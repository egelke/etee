using Egelke.Wcf.Client;
using Egelke.Wcf.Client.Security;
using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Sts
{
    public class StsBinding : Binding
    {

        public bool BypassProxyOnLocal { get; set; }

        public bool UseDefaultWebProxy { get; set; }

        public Uri ProxyAddress { get; set; }

        public StsBinding()
        {
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

        private BindingElement CreateSecurity()
        {
            return new CustomSecurityBindingElement()
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10,
                SignParts = SignParts.All
            };
        }

        private MessageEncodingBindingElement CreateMessageEncoding()
        {
            return new TextMessageEncodingBindingElement() {
                MessageVersion = MessageVersion.Soap11
            };
        }

        private TransportBindingElement CreateTransport()
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
