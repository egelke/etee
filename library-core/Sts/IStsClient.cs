using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Egelke.EHealth.Client.Sts
{
    public interface IStsClient
    {
        XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, AuthClaimSet claims);
    }
}
