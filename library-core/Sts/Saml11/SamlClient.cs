/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Sts.Saml11
{
    public class SamlClient : ClientBase<IGenericPortType>, IStsClient
    {
        private readonly ILogger _logger;
        private readonly string package;

        public SamlClient(string package, ILogger<SamlClient> logger = null)
        {
            this.package = package;
            _logger = logger ?? TraceLogger.CreateTraceLogger<SamlClient>();
        }

        public SamlClient(string package, ServiceEndpoint endpoint, ILogger<SamlClient> logger = null) :
            base(endpoint)
        {
            this.package = package;
            _logger = logger ?? TraceLogger.CreateTraceLogger<SamlClient>();
        }

        public SamlClient(string package, Binding binding, EndpointAddress remoteAddress, ILogger<SamlClient> logger = null) :
            base(binding, remoteAddress)
        {
            this.package = package;
            _logger = logger ?? TraceLogger.CreateTraceLogger<SamlClient>();
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, IList<Claim> claims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(sessionCert, notBefore, notBefore.Add(duration), claims);
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, IList<Claim> claims)
        {
            X509Certificate2 authCert = base.ClientCredentials.ClientCertificate.Certificate;

            if (package == null) throw new InvalidOperationException("package");
            if (authCert == null) throw new InvalidOperationException("Client certifciate not configured");
            if (authCert.NotBefore.ToUniversalTime() > DateTime.UtcNow || authCert.NotAfter.ToUniversalTime() <= DateTime.UtcNow) throw new ArgumentException("Expired Authentication certificate is used");

            if (sessionCert == null) throw new ArgumentNullException("sessionCert");
            if (sessionCert.NotBefore.ToUniversalTime() > notBefore || sessionCert.NotAfter.ToUniversalTime() < notOnOrAfter) throw new ArgumentException("Session certificate isn't valid during the (entire) period that is requested");
            if (notBefore == DateTime.MinValue || notBefore == DateTime.MaxValue) throw new ArgumentException("notBefore", "notBefore should be specified");
            if (notBefore.Kind != DateTimeKind.Utc) throw new ArgumentException("notBefore", "notBefore should be in UTC");
            if (notOnOrAfter == DateTime.MinValue || notOnOrAfter == DateTime.MaxValue) throw new ArgumentException("notOnOrAfter", "notOnOrAfter should be specified");
            if (notOnOrAfter.Kind != DateTimeKind.Utc) throw new ArgumentException("notOnOrAfter", "notOnOrAfter should be in UTC");
            if (claims == null) throw new ArgumentNullException("claims");

            var request = new Request()
            {
                Package = package,
                AuthCert = authCert,
                SessionCert = sessionCert,
                NotBefore = notBefore,
                NotOnOrAfter = notOnOrAfter,
                AssertingClaims = claims.Where(c => c.Resource != null).ToList(),
                AdditionalClaims = claims.Where(c => c.Resource == null).ToList()
            };
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", request);
            Message responseMsg = base.Channel.Send(requestMsg);

            Response response = new Response();
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 10240), responseMsg.Headers.Action);
            }
            response.Load(responseMsg.GetReaderAtBodyContents());
            response.Validate(package, request.RequestId);
            return response.ExtractAssertion();
        }


    }
}
