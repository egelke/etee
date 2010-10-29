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
using System.ServiceModel;
using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security.Tokens;
using System.Xml;

namespace Siemens.EHealth.Client.Sso
{
    public class SsoSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {


        public SsoSecurityTokenManager(SsoClientCredentials ssoClientCredentials)
            : base(ssoClientCredentials)
        {

        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {

            if (String.IsNullOrWhiteSpace(tokenRequirement.TokenType) ||
                tokenRequirement.TokenType == SecurityTokenTypes.Saml ||
                tokenRequirement.TokenType == "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1")
            {
                SecurityBindingElement sbe = null;
                    
                if (!tokenRequirement.TryGetProperty<SecurityBindingElement>("http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/SecurityBindingElement", out sbe))
                {
                    throw new InvalidOperationException("Could not retreive the Security Binding Element!");
                }

                // If the token requirement is for a SymmetricKey based token..
                if (tokenRequirement.KeyType != SecurityKeyType.AsymmetricKey) throw new NotSupportedException("Only Asymmetric keys are supported");
                //TODO:Add more

                return new SsoSecurityTokenProvider((SsoClientCredentials) ClientCredentials, (IssuedSecurityTokenParameters) ((AsymmetricSecurityBindingElement) sbe).InitiatorTokenParameters);
            }
            else
            {
                // otherwise use base implementation
                return base.CreateSecurityTokenProvider(tokenRequirement);
            }
        }
    }
}
