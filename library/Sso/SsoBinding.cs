/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Security;
using System.ServiceModel;
using System.IdentityModel.Claims;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens;
using System.Reflection;

namespace Siemens.EHealth.Client.Sso
{
    public class SsoBinding : WSFederationHttpBinding
    {
        public SsoBinding()
        {

        }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            if (this.Security.Mode == WSFederationHttpSecurityMode.None) throw new InvalidOperationException("Only message and  security is supported");
            if (this.Security.Message.IssuedKeyType != SecurityKeyType.AsymmetricKey) throw new InvalidOperationException("Only Asymmectric Keys are supported");
            if (this.Security.Message.NegotiateServiceCredential) throw new InvalidOperationException("Negocatiation of service credentials not supported");
            if (this.Security.Message.EstablishSecurityContext) throw new InvalidOperationException("Secure conversation not supported");

            SecurityBindingElement security;
            
            if (this.Security.Mode == WSFederationHttpSecurityMode.Message)
            {
                SymmetricSecurityBindingElement baseSecurity = (SymmetricSecurityBindingElement)base.CreateMessageSecurity();
                AsymmetricSecurityBindingElement asecurity = new AsymmetricSecurityBindingElement();
                asecurity.InitiatorTokenParameters = baseSecurity.EndpointSupportingTokenParameters.Endorsing[0];

                X509SecurityTokenParameters serverToken = new X509SecurityTokenParameters();
                serverToken.X509ReferenceStyle = X509KeyIdentifierClauseType.Any;
                serverToken.InclusionMode = SecurityTokenInclusionMode.Never;
                serverToken.RequireDerivedKeys = false;
                asecurity.RecipientTokenParameters = serverToken;
                security = asecurity;
            }
            else
            {
                TransportSecurityBindingElement baseSecurity = (TransportSecurityBindingElement)base.CreateMessageSecurity();
                TransportSecurityBindingElement tsecurity = new TransportSecurityBindingElement();

                tsecurity.EndpointSupportingTokenParameters.Endorsing.Add(baseSecurity.EndpointSupportingTokenParameters.Endorsing[0]);

                security = tsecurity;
            }

            security.EnableUnsecuredResponse = true;
            security.IncludeTimestamp = true;
            security.SecurityHeaderLayout = SecurityHeaderLayout.Lax;
            security.DefaultAlgorithmSuite = SecurityAlgorithmSuite.Basic256;
            security.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;
            security.SetKeyDerivation(false);

            return security;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection();

            elements.Add(CreateMessageSecurity());
            //elements.Add(new Wrong.WrongBindingElement());
            if (this.MessageEncoding == WSMessageEncoding.Text)
            {
                var txt = new TextMessageEncodingBindingElement(MessageVersion.Soap11, Encoding.UTF8);
                this.ReaderQuotas.CopyTo(txt.ReaderQuotas);
                elements.Add(txt);
            }
            else
            {
                var mtom = new MtomMessageEncodingBindingElement(MessageVersion.Soap11WSAddressing10, Encoding.UTF8);
                mtom.MaxBufferSize = (int)this.MaxReceivedMessageSize;
                this.ReaderQuotas.CopyTo(mtom.ReaderQuotas);
                elements.Add(mtom);
            }
            elements.Add(GetTransport());

            return elements;
        }

        protected override TransportBindingElement GetTransport()
        {
            var https = new HttpsTransportBindingElement();
            https.MaxReceivedMessageSize = this.MaxReceivedMessageSize;
            https.MaxBufferPoolSize = this.MaxBufferPoolSize;
            if (this.MessageEncoding == WSMessageEncoding.Mtom) https.TransferMode = TransferMode.Streamed;
            return https;
        }
        
    }
}
