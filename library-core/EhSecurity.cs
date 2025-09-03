using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;

namespace Egelke.EHealth.Client
{
    public class EhSecurity
    {
        public EhSecurityMode Mode { get; set; } = EhSecurityMode.X509Certificate;

        public Binding IssuerBinding { get; set; } = null;

        public EndpointAddress IssuerAddress { get; set; } = null;

        public X509CertificateInitiatorClientCredential SessionCertificate { get; set; } = null;


        internal InitiatorServiceModelSecurityTokenRequirement ToTokenRequirement(EndpointAddress targetAddress)
        {
            return new InitiatorServiceModelSecurityTokenRequirement()
            {
                TokenType = Mode.ToTokenType(),
                IssuerBinding = IssuerBinding ?? new EhBinding(),
                IssuerAddress = IssuerAddress,
                TargetAddress = targetAddress
            };
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
