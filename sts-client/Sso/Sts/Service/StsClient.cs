/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.Net.Security;
using System.ServiceModel;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Claims;
using System.IO;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;

namespace Siemens.EHealth.Client.Sso.Sts.Service
{
    [ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "urn:be:fgov:ehealth:sts:protocol:v1", ConfigurationName = "StsV1", Name = "SecureTokenServicePort")]
    public interface StsPortType
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message RequestSecureToken(Message request);
    }

    public class StsClient : ClientBase<StsPortType>
    {


        public StsClient()
        {
        }

        public StsClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public StsClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public StsClient(string endpointConfigurationName, EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public StsClient(Binding binding, EndpointAddress remoteAddress) :
            base(binding, remoteAddress)
        {
        }

        public XmlElement RequestTicket(String package, X509Certificate2 sessionCert, TimeSpan duration, Collection<XmlElement> assertingClaims, Collection<ClaimTypeRequirement> requestedClaims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(package, sessionCert, notBefore, notBefore.Add(duration), assertingClaims, requestedClaims);
        }

        public XmlElement RequestTicket(String package, X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, Collection<XmlElement> assertingClaims, Collection<ClaimTypeRequirement> requestedClaims)
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

            Message requestMsg;
            Request request = new Request(package, authCert, sessionCert, notBefore, notOnOrAfter, assertingClaims, requestedClaims);
            MemoryStream buffer = new MemoryStream();
            XmlWriter writer = XmlWriter.Create(buffer);
            using (writer)
            {
                request.Save(writer);
                writer.Flush();

                buffer.Position = 0;
                XmlReader reader = XmlReader.Create(buffer);
                requestMsg = Message.CreateMessage(MessageVersion.Soap11, "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecureToken", reader);
            }
            Message responseMsg = base.Channel.RequestSecureToken(requestMsg);

            Response response = new Response();
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 1024));
            }
            response.Load(responseMsg.GetReaderAtBodyContents());
            response.Validate(package, request.RequestId);
            return response.ExtractAssertion();
        }


    }
}
