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
    public class CustomSecurity
    {
        public EhSecurityMode Mode { get; set; } = EhSecurityMode.X509Certificate;

        public Binding IssuerBinding { get; set; } = null;

        public EndpointAddress IssuerAddress { get; set; } = null;

        public AuthClaimSet AuthClaims { get; } = new AuthClaimSet();

        public CustomSecurityClientCredential SessionCertificate { get; } = new CustomSecurityClientCredential();

        public TimeSpan SessionDuration { get; set; } = TimeSpan.FromHours(1);

        public IMemoryCache Cache { get; set; }

        public SecurityVersion SecurityVersion = SecurityVersion.WSSecurity11;

        public CustomSecurity()
        {

        }

        public CustomSecurity(SecurityVersion securityVersion)
        {
            this.SecurityVersion = securityVersion;
        }

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

    public enum EhSecurityMode
    {
        X509Certificate,
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
