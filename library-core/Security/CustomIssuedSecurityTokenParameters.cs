using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Egelke.EHealth.Client.Sts;

namespace Egelke.EHealth.Client.Security
{
    public class CustomIssuedSecurityTokenParameters : IssuedSecurityTokenParameters
    {
        internal const string Namespace = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement";
        internal const string IssuedSecurityTokenParametersProperty = Namespace + "/IssuedSecurityTokenParameters";

        public AuthClaimSet AuthClaims { get; }

        public X509Certificate2 SessionCertificate { get; }

        public CustomIssuedSecurityTokenParameters(AuthClaimSet authClaims, X509Certificate2 sessionCertificate) : base() 
        { 
            this.AuthClaims = authClaims;
            this.SessionCertificate = sessionCertificate;
        }

        protected CustomIssuedSecurityTokenParameters(CustomIssuedSecurityTokenParameters other) : base(other)
        {
            this.AuthClaims = (AuthClaimSet) other.AuthClaims.Clone();
            this.SessionCertificate = other.SessionCertificate;
        }
        
    }
}
