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
using System.ServiceModel;
using System.IdentityModel.Selectors;
using System.ServiceModel.Security.Tokens;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Description;

namespace Siemens.EHealth.Client.Sso.WA
{
    public class OptSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        private bool isDummyServiceToken = false; 

        public OptSecurityTokenManager(ClientCredentials clientCredentials)
            : base(clientCredentials)
        {

        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            InitiatorServiceModelSecurityTokenRequirement requirement = tokenRequirement as InitiatorServiceModelSecurityTokenRequirement;
            if (requirement != null
                && requirement.TokenType == SecurityTokenTypes.X509Certificate
                && requirement.Properties.ContainsKey(SecurityTokenRequirement.KeyUsageProperty) && (requirement.KeyUsage == SecurityKeyUsage.Exchange))
            {
                X509Certificate2 defaultCertificate = null;
                EndpointAddress targetAddress = requirement.TargetAddress;
                if (targetAddress != null)
                {
                    this.ClientCredentials.ServiceCertificate.ScopedCertificates.TryGetValue(targetAddress.Uri, out defaultCertificate);
                }
                if (defaultCertificate == null)
                {
                    defaultCertificate = this.ClientCredentials.ServiceCertificate.DefaultCertificate;
                }
                if (((defaultCertificate == null) && (targetAddress.Identity != null)) && (targetAddress.Identity.GetType() == typeof(X509CertificateEndpointIdentity)))
                {
                    defaultCertificate = ((X509CertificateEndpointIdentity)targetAddress.Identity).Certificates[0];
                }
                if (defaultCertificate == null)
                {
                    isDummyServiceToken = true;
                    return new DummySecurityTokenProvider();
                }
                isDummyServiceToken = false;
                return new X509SecurityTokenProvider(defaultCertificate);
            }
            return base.CreateSecurityTokenProvider(tokenRequirement);
        }

        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
        {
            InitiatorServiceModelSecurityTokenRequirement requirement = tokenRequirement as InitiatorServiceModelSecurityTokenRequirement;
            if (isDummyServiceToken
                && requirement != null
                && requirement.TokenType == SecurityTokenTypes.X509Certificate
                && requirement.Properties.ContainsKey(SecurityTokenRequirement.KeyUsageProperty) && (requirement.KeyUsage == SecurityKeyUsage.Exchange))
            {
                outOfBandTokenResolver = null;
                return new DummySecurityTokenAuthenticator(requirement.TargetAddress.Uri);
            }
            return base.CreateSecurityTokenAuthenticator(tokenRequirement, out outOfBandTokenResolver);
        }

    }
}
