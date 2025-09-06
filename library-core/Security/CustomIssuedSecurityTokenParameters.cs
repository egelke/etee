using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Egelke.EHealth.Client.Sts;

namespace Egelke.EHealth.Client.Security
{
    public class CustomIssuedSecurityTokenParameters : IssuedSecurityTokenParameters
    {
        private const string ID_PART_DELIMITER = "\n";
        private const string CERT_ISSUES_DELIMITER = "@";
        private const string CLAIM_VALUE_DELIMITER = "=";
        private const string EMPTY_VALUE_TEXT = "<null>";


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


        public string ToId(X509Certificate2 idCert)
        {
            StringBuilder sb = new StringBuilder();

            //the STS's uri
            sb.Append(IssuerAddress.Uri.AbsoluteUri);

            //the ID cert
            AppendTo(sb, idCert);

            //The Session cert
            AppendTo(sb, SessionCertificate);

            //The claims, ordered 
            foreach(Claim claim in AuthClaims.OrderBy(c => c.ClaimType))
            {
                sb.Append(ID_PART_DELIMITER)
                    .Append(claim.ClaimType)
                    .Append(CLAIM_VALUE_DELIMITER)
                    .Append(claim.Resource ?? EMPTY_VALUE_TEXT);
            }

            return sb.ToString();
        }

        private void AppendTo(StringBuilder sb, X509Certificate2 cert)
        {
            sb.Append(ID_PART_DELIMITER);
            AppendTo(sb, cert?.SubjectName);
            sb.Append(CERT_ISSUES_DELIMITER);
            AppendTo(sb, cert?.IssuerName);
        }

        private void AppendTo(StringBuilder sb, X500DistinguishedName name)
        {
            sb.Append(name?.Decode(X500DistinguishedNameFlags.DoNotUsePlusSign | X500DistinguishedNameFlags.UseSemicolons | X500DistinguishedNameFlags.DoNotUseQuotes | X500DistinguishedNameFlags.UseUTF8Encoding) ?? EMPTY_VALUE_TEXT);
        }
    }
}
