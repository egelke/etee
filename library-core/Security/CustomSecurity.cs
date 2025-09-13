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
using System.IdentityModel.Selectors;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Security;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Caching.Memory;

namespace Egelke.EHealth.Client
{
    /// <summary>
    /// Custom WCF Security configuration for eHealth.
    /// </summary>
    public class CustomSecurity
    {
        /// <summary>
        /// eHealth security mode (X509 or WS-Trust), defaults to X509.
        /// </summary>
        public EhSecurityMode Mode { get; set; } = EhSecurityMode.X509Certificate;

        /// <summary>
        /// Binding to use with the STS (WS-Trust only), defaults to null (= default EhBinding)
        /// </summary>
        public Binding IssuerBinding { get; set; } = null;

        /// <summary>
        /// The address (url) of the STS that will issue the token (WS-Trust only)
        /// </summary>
        public EndpointAddress IssuerAddress { get; set; } = null;

        /// <summary>
        /// Set of authentication claims to provide with the request (WS-Trust only), defaults to an empty list
        /// </summary>
        public AuthClaimSet AuthClaims { get; } = new AuthClaimSet();

        /// <summary>
        /// Configuration that specifies the "session" or HOK certificate to use.
        /// </summary>
        public CustomSecurityClientCredential SessionCertificate { get; } = new CustomSecurityClientCredential();

        /// <summary>
        /// The duration to reques for the token, defaults to 1 hours.
        /// </summary>
        public TimeSpan SessionDuration { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Cache for the tokens, defaults to null (=global memory cache).
        /// </summary>
        public IMemoryCache Cache { get; set; }

        /// <summary>
        /// WS-Security version, default to 1.1
        /// </summary>
        /// <remarks>
        /// None of the v1.1 specific elements are currently supported.
        /// </remarks>
        public SecurityVersion SecurityVersion = SecurityVersion.WSSecurity11;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public CustomSecurity()
        {

        }

        /// <summary>
        /// Copy constructor.
        /// </summary>
        /// <param name="securityVersion">instance to copy from</param>
        public CustomSecurity(SecurityVersion securityVersion)
        {
            this.SecurityVersion = securityVersion;
        }

        /// <summary>
        /// Optains the token requirement for the current configuration.
        /// </summary>
        /// <param name="targetAddress">service that the token requirement will be used with</param>
        /// <returns>standard token requirement with the eHealth specific properties</returns>
        /// <seealso cref="CustomIssuedSecurityTokenParameters"/>
        internal SecurityTokenRequirement ToTokenRequirement(EndpointAddress targetAddress)
        {
            var tokenRequirement = new SecurityTokenRequirement()
            {
                TokenType = Mode.ToTokenType(),
            };
            tokenRequirement.Properties["wss"] = WSS.Create(SecurityVersion);
            if (Mode == EhSecurityMode.SamlFromWsTrust)
            {
                var issuedtokenParameters = new CustomIssuedSecurityTokenParameters(AuthClaims, SessionCertificate.Certificate, SessionDuration)
                {
                    IssuerAddress = IssuerAddress,
                    IssuerBinding = IssuerBinding ?? new EhBinding(),
                    Cache = Cache,
                };

                tokenRequirement.Properties[CustomIssuedSecurityTokenParameters.IssuedSecurityTokenParametersProperty] = issuedtokenParameters;
            }
            return tokenRequirement;
        }
    }

    /// <summary>
    /// Types of eHealth security modes that are supported.
    /// </summary>
    public enum EhSecurityMode
    {
        /// <summary>
        /// WS-Security with a BTS that is an X509-Certificate.
        /// </summary>
        /// <remarks>
        /// While pretty standard, eHealth requires body and BTS to be also signed which isn't
        /// supported out of the box by WCF.
        /// </remarks>
        X509Certificate,
        /// <summary>
        /// WS-Security with a Saml1.1 token obtained using a WS-Trust service.
        /// </summary>
        /// <remarks>
        /// Requires a HOK that is a (provided) X509Certificate as asymetric key; the WCF implementations 
        /// are very limited and focus on generated symetric keys.
        /// </remarks>
        SamlFromWsTrust
    }

    internal static class EhSecurityModeExtensions
    {
        public static string ToTokenType(this EhSecurityMode mode)
        {
            switch (mode)
            {
                case EhSecurityMode.X509Certificate:
                    return "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate";
                case EhSecurityMode.SamlFromWsTrust:
                    return "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml";
                default:
                    throw new ArgumentException("Unsupported Mode");
            }
        }
    }
}
