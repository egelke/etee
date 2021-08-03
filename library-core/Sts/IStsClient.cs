using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Egelke.EHealth.Client.Sts
{
    public interface IStsClient
    {
        XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, IList<Claim> assertingClaims, IList<Claim> requestedClaims);

        //Task<XmlElement> RequestTicketAsync(X509Certificate2 sessionCert, TimeSpan duration, IList<XmlElement> assertingClaims, IList<XmlElement> requestedClaims);
    }
}
