/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
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
            if (this.Security.Mode != WSFederationHttpSecurityMode.Message) throw new InvalidOperationException("Only message security is supported");
            if (this.Security.Message.IssuedKeyType != SecurityKeyType.AsymmetricKey) throw new InvalidOperationException("Only Asymmectric Keys are supported");
            if (this.Security.Message.NegotiateServiceCredential) throw new InvalidOperationException("Negocatiation of service credentials not supported");
            if (this.Security.Message.EstablishSecurityContext) throw new InvalidOperationException("Secure conversation not supported");

            SymmetricSecurityBindingElement baseSecurity = (SymmetricSecurityBindingElement) base.CreateMessageSecurity();
            
            AsymmetricSecurityBindingElement security = new AsymmetricSecurityBindingElement();
            security.InitiatorTokenParameters = baseSecurity.EndpointSupportingTokenParameters.Endorsing[0];

            X509SecurityTokenParameters serverToken = new X509SecurityTokenParameters();
            serverToken.X509ReferenceStyle = X509KeyIdentifierClauseType.Any;
            serverToken.InclusionMode = SecurityTokenInclusionMode.Never;
            serverToken.RequireDerivedKeys = false;
            security.RecipientTokenParameters = serverToken;

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
            elements.Add(new TextMessageEncodingBindingElement(MessageVersion.Soap11, Encoding.UTF8));
            elements.Add(GetTransport());

            return elements;
        }

        protected override TransportBindingElement GetTransport()
        {
            return new HttpsTransportBindingElement();
        }
        
    }
}
