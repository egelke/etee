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
    /// <summary>
    /// WCF Client for SAML-P Service of eHealth.
    /// </summary>
    public class SamlClient : ClientBase<IGenericPortType>, IStsClient
    {
        private readonly ILogger<SamlClient> _logger;
        private readonly string package;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="package">The id of the software package</param>
        /// <param name="logger">optional logger</param>
        public SamlClient(string package, ILogger<SamlClient> logger = null)
        {
            this.package = package;
            _logger = logger;
        }

        /// <summary>
        /// Constructor with custom endpoint
        /// </summary>
        /// <param name="package">The id of the software package</param>
        /// <param name="endpoint">custom endpoint of the SAML-P service</param>
        /// <param name="logger">optional logger</param>
        public SamlClient(string package, ServiceEndpoint endpoint, ILogger<SamlClient> logger = null) :
            base(endpoint)
        {
            this.package = package;
            _logger = logger;
        }

        /// <summary>
        /// Constructor with custom binding and endpoint
        /// </summary>
        /// <param name="package">The id of the software package</param>
        /// <param name="binding">Custom binding to use</param>
        /// <param name="remoteAddress">custom endpoint of the SAML-P service</param>
        /// <param name="logger">optional logger</param>
        public SamlClient(string package, Binding binding, EndpointAddress remoteAddress, ILogger<SamlClient> logger = null) :
            base(binding, remoteAddress)
        {
            this.package = package;
            _logger = logger;
        }

        /// <summary>
        /// Create a new ticket for the requested duration.
        /// </summary>
        /// <param name="sessionCert">The HOK certificate to use</param>
        /// <param name="duration">The requested duration</param>
        /// <param name="claims">The claims to provide with the request, 
        /// will be split in asserting and additional claims depending on the value</param>
        /// <returns>A SAMLv1.1 Assertion as a Xml DOM element</returns>
        public XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, AuthClaimSet claims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(sessionCert, notBefore, notBefore.Add(duration), claims);
        }

        /// <summary>
        /// Create a new ticket for the requested duration.
        /// </summary>
        /// <param name="sessionCert">The HOK certificate to use</param>
        /// <param name="notBefore">start time of the token</param>
        /// <param name="notOnOrAfter">end time of the token</param>
        /// <param name="claims">The claims to provide with the request, 
        /// will be split in asserting and additional claims depending on the value</param>
        /// <returns>A SAMLv1.1 Assertion as a Xml DOM element</returns>
        public XmlElement RequestTicket(X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, AuthClaimSet claims)
        {
            X509Certificate2 authCert = base.ClientCredentials.ClientCertificate.Certificate;

            if (package == null) throw new InvalidOperationException("package");
            if (authCert == null) throw new InvalidOperationException("Client certifciate not configured");
            if (authCert.NotBefore.ToUniversalTime() > DateTime.UtcNow || authCert.NotAfter.ToUniversalTime() <= DateTime.UtcNow) throw new ArgumentException("Expired Authentication certificate is used");

            if (sessionCert == null) throw new ArgumentNullException(nameof(sessionCert));
            if (sessionCert.NotBefore.ToUniversalTime() > notBefore || sessionCert.NotAfter.ToUniversalTime() < notOnOrAfter) throw new ArgumentException("Session certificate isn't valid during the (entire) period that is requested");
            if (notBefore == DateTime.MinValue || notBefore == DateTime.MaxValue) throw new ArgumentException("notBefore should be specified", nameof(notBefore));
            if (notBefore.Kind != DateTimeKind.Utc) throw new ArgumentException("notBefore should be in UTC", nameof(notBefore));
            if (notOnOrAfter == DateTime.MinValue || notOnOrAfter == DateTime.MaxValue) throw new ArgumentException("notOnOrAfter should be specified", nameof(notOnOrAfter));
            if (notOnOrAfter.Kind != DateTimeKind.Utc) throw new ArgumentException("notOnOrAfter should be in UTC", nameof(notOnOrAfter));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

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
