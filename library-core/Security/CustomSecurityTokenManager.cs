using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityTokenManager : SecurityTokenManager
    {
        public override SecurityTokenAuthenticator CreateSecurityTokenAuthenticator(SecurityTokenRequirement tokenRequirement, out SecurityTokenResolver outOfBandTokenResolver)
        {
            throw new NotImplementedException();
            
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            throw new NotImplementedException();
        }

        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            throw new NotImplementedException();
        }
    }
}
