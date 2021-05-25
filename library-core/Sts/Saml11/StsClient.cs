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
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.ServiceModel;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Egelke.Wcf.Client.Helper;

namespace Egelke.Wcf.Client.Sts.Saml11
{
    [ServiceContract(Namespace = "urn:be:fgov:ehealth:sts:protocol:v1", ConfigurationName = "StsSaml11", Name = "Saml11TokenServicePortType")]
    public interface StsPortType
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message RequestSecureToken(Message request);
    }

    public class StsClient : ClientBase<StsPortType>
    {
        private readonly ILogger _logger;

        public StsClient(ILogger<StsClient> logger = null)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<StsClient>();
        }

        public StsClient(string endpointConfigurationName, ILogger<StsClient> logger = null) :
            base(endpointConfigurationName)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<StsClient>();
        }

        public StsClient(string endpointConfigurationName, string remoteAddress, ILogger<StsClient> logger = null) :
            base(endpointConfigurationName, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<StsClient>();
        }

        public StsClient(string endpointConfigurationName, EndpointAddress remoteAddress, ILogger<StsClient> logger = null) :
            base(endpointConfigurationName, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<StsClient>();
        }

        public StsClient(Binding binding, EndpointAddress remoteAddress, ILogger<StsClient> logger = null) :
            base(binding, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<StsClient>();
        }

        public XmlElement RequestTicket(String package, X509Certificate2 sessionCert, TimeSpan duration, IList<XmlElement> assertingClaims, IList<XmlElement> requestedClaims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(package, sessionCert, notBefore, notBefore.Add(duration), assertingClaims, requestedClaims);
        }

        public XmlElement RequestTicket(String package, X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, IList<XmlElement> assertingClaims, IList<XmlElement> requestedClaims)
        {
            X509Certificate2 authCert = base.ClientCredentials.ClientCertificate.Certificate;

            if (package == null) throw new ArgumentNullException("package");
            if (sessionCert == null) throw new ArgumentNullException("sessionCert");
            if (notBefore == DateTime.MinValue || notBefore == DateTime.MaxValue) throw new ArgumentException("notBefore", "notBefore should be specified");
            if (notBefore.Kind != DateTimeKind.Utc) throw new ArgumentException("notBefore", "notBefore should be in UTC");
            if (notOnOrAfter == DateTime.MinValue || notOnOrAfter == DateTime.MaxValue) throw new ArgumentException("notOnOrAfter", "notOnOrAfter should be specified");
            if (notOnOrAfter.Kind != DateTimeKind.Utc) throw new ArgumentException("notOnOrAfter", "notOnOrAfter should be in UTC");
            if (assertingClaims == null) throw new ArgumentNullException("assertingClaims");
            if (assertingClaims.Count == 0) throw new ArgumentOutOfRangeException("assertingClaims", "assertingClaims should at least contain one claim");
            if (requestedClaims == null) throw new ArgumentNullException("requestedClaims");
            if (requestedClaims.Count == 0) throw new ArgumentOutOfRangeException("requestedClaims", "requestedClaims should at least contain one claim");
            if (authCert == null) throw new InvalidOperationException("Client certifciate not configured");
            if (authCert.NotBefore.ToUniversalTime() > DateTime.UtcNow || authCert.NotAfter.ToUniversalTime() <= DateTime.UtcNow) throw new ArgumentException("Expired Authentication certificate is used");
            if (sessionCert.NotBefore.ToUniversalTime() > notBefore || sessionCert.NotAfter.ToUniversalTime() < notOnOrAfter) throw new ArgumentException("Session certificate isn't valid during the (entire) period that is requested");

            var request = new Request()
            {
                Package = package,
                AuthCert = authCert,
                SessionCert = sessionCert,
                NotBefore = notBefore,
                NotOnOrAfter = notOnOrAfter,
                AssertingClaims = assertingClaims,
                RequestedClaims = requestedClaims
            };
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", request);
            Message responseMsg = base.Channel.RequestSecureToken(requestMsg);

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
