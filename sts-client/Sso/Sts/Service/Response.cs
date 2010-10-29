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
using System.Xml;

namespace Siemens.EHealth.Client.Sso.Sts.Service
{
    public class Response
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        private const String saml = "urn:oasis:names:tc:SAML:1.0:assertion";

        private readonly XmlDocument body;

        private XmlElement response;

        private readonly XmlNamespaceManager nsmngr;

        public Response()
        {
            body = new XmlDocument();
            body.PreserveWhitespace = true;

            nsmngr = new XmlNamespaceManager(body.NameTable);
            nsmngr.AddNamespace("samlp", samlp);
            nsmngr.AddNamespace("saml", saml);
        }

        public void Load(XmlReader xml)
        {
            body.Load(xml);
            response = body.DocumentElement;
            if (response.NamespaceURI != samlp || response.LocalName != "Response") throw new SamlException(String.Format("Expected samlp:Reponse but received {{{0}}}{1}", response.NamespaceURI, response.LocalName));
        }

        public void Validate(String package, String requestId)
        {
            if (package != response.Attributes["Recipient"].Value) throw new SamlException(String.Format("The recipient and the package do not correspond. Expected {0}, Actual {1}", package, response.Attributes["Recipient"].Value));
            if (requestId != response.Attributes["InResponseTo"].Value) throw new SamlException(String.Format("The reponse isn't for this request. Expected {0}, Actual {1}",requestId, response.Attributes["InResponseTo"].Value));
        }

        public XmlElement ExtractAssertion()
        {
            
            XmlElement statusElement = (XmlElement) response.SelectSingleNode("samlp:Status", nsmngr);
            if (statusElement == null) throw new SamlException("Received samlp:Response does not contain a Status element");

            XmlElement statusCode = (XmlElement)statusElement.SelectSingleNode("samlp:StatusCode", nsmngr);
            if (statusCode == null) throw new SamlException("Received samlp:Response/samlp:Status does not contain a StatusCode element");

            StatusCode status = StatusCode.Parse(statusCode);
            if (!status.IsSuccess)
            {
                String msg = null;
                XmlNode statusMsgNode = statusElement.SelectSingleNode("samlp:StatusMessage/text()", nsmngr);
                if (statusMsgNode != null) msg = statusMsgNode.Value;

                XmlNodeList detail = statusElement.SelectNodes("samlp:StatusDetail/*", nsmngr);

                throw new SamlFault(status, msg, detail);
            }

            return (XmlElement)response.SelectSingleNode("saml:Assertion", nsmngr);
        }

        
    }
}
