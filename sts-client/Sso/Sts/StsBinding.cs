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
using Siemens.EHealth.Client.Sso.Sts.WcfAddition;

namespace Siemens.EHealth.Client.Sso.Sts
{
    public class StsBinding : Binding
    {
        private SecurityBindingElement security;

        private MessageEncodingBindingElement messageEncoding;

        private TransportBindingElement transport;

        public StsBinding()
        {
            security = CreateSecurity();
            messageEncoding = CreateMessageEncoding();
            transport = CreateTransport();
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection();
            elements.Add(security);
            elements.Add(new EHealthBindingElement());
            elements.Add(messageEncoding);
            elements.Add(transport);
            
            return elements.Clone();
        }



        private SecurityBindingElement CreateSecurity()
        {
            AsymmetricSecurityBindingElement security = new AsymmetricSecurityBindingElement();

            X509SecurityTokenParameters clientToken = new X509SecurityTokenParameters();
            clientToken.X509ReferenceStyle = X509KeyIdentifierClauseType.Any;
            clientToken.InclusionMode = SecurityTokenInclusionMode.AlwaysToRecipient;
            clientToken.RequireDerivedKeys = false;
            clientToken.ReferenceStyle = SecurityTokenReferenceStyle.Internal;
            security.InitiatorTokenParameters = clientToken; //Creates an _unsigned_ binary token + signature that references the other binary token.

            X509SecurityTokenParameters serverToken = new X509SecurityTokenParameters();
            serverToken.X509ReferenceStyle = X509KeyIdentifierClauseType.Any;
            serverToken.InclusionMode = SecurityTokenInclusionMode.Never;
            serverToken.RequireDerivedKeys = false;
            serverToken.ReferenceStyle = SecurityTokenReferenceStyle.External;
            security.RecipientTokenParameters = serverToken; //Only to make asymetric binding work

            security.EndpointSupportingTokenParameters.Signed.Add(clientToken); //Create a signed binary token + signature that does _not_ references other binary token.
            //Later on the unsigned binary token is removed and the non referecing signature is removed.  The signed token and referencing signature are linked.

            security.EnableUnsecuredResponse = true;
            security.IncludeTimestamp = true;
            security.SecurityHeaderLayout = SecurityHeaderLayout.Lax;
            security.DefaultAlgorithmSuite = SecurityAlgorithmSuite.Basic256;
            security.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;
            security.SetKeyDerivation(false);

            return security;
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
            transport.HostNameComparisonMode = HostNameComparisonMode.WeakWildcard;
            
            return transport;
        }

        public override string Scheme
        {
            get { return "https"; }
        }
    }
}
