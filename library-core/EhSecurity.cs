using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;

namespace Egelke.EHealth.Client
{
    public class EhSecurity
    {
        public EhSecurityMode Mode { get; set; }

        public EndpointAddress IssuerAddress { get; set; } = null;

        public X509CertificateInitiatorClientCredential SessionCredential {  get; set; }

        public EhSecurity()
            : this(EhSecurityMode.X509Certificate)
        {

        }

        public EhSecurity(EhSecurityMode mode)
        {
            Mode = mode;
        }
    }

    public enum EhSecurityMode
    {
        X509Certificate,
        SamlFromWsTrust
    }
}
