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
using System.Linq;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Sts.Saml11
{
    /// <summary>
    /// SAML-P v1.1 Response object.
    /// </summary>
    internal class Response
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        private const String saml = "urn:oasis:names:tc:SAML:1.0:assertion";

        private readonly XmlDocument body;

        private XmlElement response;

        private readonly XmlNamespaceManager nsmngr;

        /// <summary>
        /// Default constructor
        /// </summary>
        public Response()
        {
            body = new XmlDocument
            {
                PreserveWhitespace = true
            };

            nsmngr = new XmlNamespaceManager(body.NameTable);
            nsmngr.AddNamespace("samlp", samlp);
            nsmngr.AddNamespace("saml", saml);
        }

        /// <summary>
        /// Load the response from XML.
        /// </summary>
        /// <param name="xml">The xml as reader</param>
        /// <exception cref="StsException">When the xml wasn't a SAML-P 1.1 response</exception>
        public void Load(XmlReader xml)
        {
            body.Load(xml);
            response = body.DocumentElement;
            if (response.NamespaceURI != samlp || response.LocalName != "Response") throw new StsException(String.Format("Expected samlp:Reponse but received {{{0}}}{1}", response.NamespaceURI, response.LocalName));
        }

        /// <summary>
        /// Check the response
        /// </summary>
        /// <param name="package">the package, i.e. the expected Recipient</param>
        /// <param name="requestId">The rquest id, i.e. the expected In Response To</param>
        /// <exception cref="StsException"></exception>
        public void Validate(String package, String requestId)
        {
            if (response.Attributes["Recipient"] != null && package != response.Attributes["Recipient"].Value) throw new StsException(String.Format("The recipient and the package do not correspond. Expected {0}, Actual {1}", package, response.Attributes["Recipient"].Value));
            if (requestId != response.Attributes["InResponseTo"].Value) throw new StsException(String.Format("The reponse isn't for this request. Expected {0}, Actual {1}",requestId, response.Attributes["InResponseTo"].Value));
        }

        /// <summary>
        /// Extract the SAML Assertion from the SAML-P response
        /// </summary>
        /// <returns>The Assertion element</returns>
        /// <exception cref="StsException">The response isn't a proper SAML-P</exception>
        /// <exception cref="SamlFault">The SAML-P response returned an error code</exception>
        public XmlElement ExtractAssertion()
        {
            
            XmlElement statusElement = (XmlElement) response.SelectSingleNode("samlp:Status", nsmngr) ?? throw new StsException("Received samlp:Response does not contain a Status element");

            XmlElement statusCode = (XmlElement)statusElement.SelectSingleNode("samlp:StatusCode", nsmngr) ?? throw new StsException("Received samlp:Response/samlp:Status does not contain a StatusCode element");

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
