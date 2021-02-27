using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Sts
{
    public class StsBinding : Binding
    {
        //private SecurityBindingElement security;

        private MessageEncodingBindingElement messageEncoding;

        private TransportBindingElement transport;

        public StsBinding()
        {
            //security = CreateSecurity();
            messageEncoding = CreateMessageEncoding();
            transport = CreateTransport();
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection();
            elements.Add(messageEncoding);
            elements.Add(transport);
            return elements.Clone();
        }

        private MessageEncodingBindingElement CreateMessageEncoding()
        {
            TextMessageEncodingBindingElement encoding = new TextMessageEncodingBindingElement();
            encoding.MessageVersion = MessageVersion.Soap11;
            return encoding;
        }

        private TransportBindingElement CreateTransport()
        {
            HttpsTransportBindingElement transport = new HttpsTransportBindingElement();
            transport.AuthenticationScheme = System.Net.AuthenticationSchemes.Anonymous;
            //transport.HostNameComparisonMode = HostNameComparisonMode.WeakWildcard;

            return transport;
        }

        public override string Scheme => transport.Scheme;
    }
}
