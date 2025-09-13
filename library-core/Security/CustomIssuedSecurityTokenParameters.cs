/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Caching.Memory;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom Issued Security Token Paramters for eHealth.
    /// </summary>
    public class CustomIssuedSecurityTokenParameters : IssuedSecurityTokenParameters
    {
        private const string ID_PART_DELIMITER = "\n";
        private const string CERT_ISSUES_DELIMITER = "@";
        private const string CLAIM_VALUE_DELIMITER = "=";
        private const string EMPTY_VALUE_TEXT = "<null>";

        internal const string Namespace = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement";
        internal const string IssuedSecurityTokenParametersProperty = Namespace + "/IssuedSecurityTokenParameters";

        private static readonly IMemoryCache DEFAULT_CACHE = new MemoryCache(new MemoryCacheOptions()
        {
            SizeLimit = 1024,
        });

        /// <summary>
        /// Set of authentication claims used to request the token.
        /// </summary>
        public AuthClaimSet AuthClaims { get; }

        /// <summary>
        /// Certificate to use as HOK
        /// </summary>
        public X509Certificate2 SessionCertificate { get; }

        /// <summary>
        /// Requested duration of the token.
        /// </summary>
        public TimeSpan SessionDuration { get; }

        private IMemoryCache _cache;

        /// <summary>
        /// Memory Cache for the tokens.
        /// </summary>
        /// <remarks>
        /// A cache is mandatory to allow reuse of previously issued tokens.
        /// </remarks>
        /// <value>
        /// null means the default cache.
        /// </value>
        public IMemoryCache Cache {
            get => _cache ?? DEFAULT_CACHE;
            set { _cache = value; }
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="authClaims">set of authentication claim to use</param>
        /// <param name="sessionCertificate">HOK certificate to use</param>
        /// <param name="sessionDuration">Duration of token to request</param>
        public CustomIssuedSecurityTokenParameters(AuthClaimSet authClaims, X509Certificate2 sessionCertificate, TimeSpan sessionDuration) : base() 
        { 
            this.AuthClaims = authClaims;
            this.SessionCertificate = sessionCertificate;
            this.SessionDuration = sessionDuration;
        }

        /// <summary>
        /// Copy constructor.
        /// </summary>
        /// <param name="other">The instance to copy from</param>
        protected CustomIssuedSecurityTokenParameters(CustomIssuedSecurityTokenParameters other) : base(other)
        {
            this.AuthClaims = (AuthClaimSet) other.AuthClaims.Clone();
            this.SessionCertificate = other.SessionCertificate;
            this.SessionDuration = other.SessionDuration;
        }

        /// <summary>
        /// Return the Id of the instance.
        /// </summary>
        /// <remarks>
        /// Used by cache to check which request parameters are identical.
        /// </remarks>
        /// <param name="idCert">the subjects certificate that will be used to obtain the thoken</param>
        /// <returns>string constructed of: sts-uri, subject cert, session cert and claims</returns>
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
