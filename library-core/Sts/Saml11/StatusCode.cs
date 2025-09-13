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
    /// Object for the SAML v1.1 status code structure.
    /// </summary>
    public class StatusCode
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        /// <summary>
        /// Parses SAML v1.1. status code structure and its child-elements.
        /// </summary>
        /// <param name="statusCode">The top level status code element</param>
        /// <returns>the object representation of the status cude</returns>
        /// <exception cref="StsException">The provided xml element is not a valid status code structure</exception>
        public static StatusCode Parse(XmlElement statusCode)
        {
            XmlNamespaceManager nsmngr = new XmlNamespaceManager(statusCode.OwnerDocument.NameTable);
            nsmngr.AddNamespace("samlp", samlp);

            XmlAttribute statusCodeValue = statusCode.Attributes["Value"] ?? throw new StsException("sampl:StatusCode does not contain a Value attribute");
            String[] parts = statusCodeValue.Value.Split(':');
            String codeValueNs;
            String codeValueLocal;
            switch (parts.Length)
            {
                case 1:
                    codeValueNs = statusCodeValue.GetNamespaceOfPrefix("");
                    codeValueLocal = parts[0];
                    break;
                case 2:
                    codeValueNs = statusCodeValue.GetNamespaceOfPrefix(parts[0]);
                    codeValueLocal = parts[1];
                    break;
                default:
                    throw new StsException(String.Format("Illegal sampl:StatusCode/@Value content: {0}", statusCodeValue.Value));
            }

            StatusCode subStatus = null;
            XmlElement subStatusCode = (XmlElement) statusCode.SelectSingleNode("samlp:StatusCode", nsmngr);
            if (subStatusCode != null)
            {
                subStatus = Parse(subStatusCode); 
            }
            return new StatusCode(codeValueLocal, codeValueNs, subStatus);
        }

        private readonly String name;
        private readonly String ns;
        private readonly StatusCode subStatus;

        private StatusCode(string name, string ns, StatusCode subStatus)
        {
            this.name = name;
            this.ns = ns;
            this.subStatus = subStatus;
        }

        /// <summary>
        /// The local name part of the status code value.
        /// </summary>
        public String Name
        {
            get
            {
                return name;
            }
        }

        /// <summary>
        /// The namespace part of the status code value.
        /// </summary>
        public String Namespace
        {
            get
            {
                return ns;
            }
        }

        /// <summary>
        /// The sub-status, if present; otherwise null.
        /// </summary>
        public StatusCode SubStatus
        {
            get
            {
                return subStatus;
            }
        }

        /// <summary>
        /// Check the name and ns to be equal to samlp:Success.
        /// </summary>
        public bool IsSuccess
        {
            get
            {
                return ns == samlp && name == "Success";
            }
        }
    }
}
