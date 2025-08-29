using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {

        public CustomSecurityTokenManager(ClientCredentials clientCredentials)
            : base(clientCredentials) { }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            return new CustomSecurityTokenProvider(tokenRequirement, ClientCredentials.ClientCertificate.Certificate);
        }
    }
}
