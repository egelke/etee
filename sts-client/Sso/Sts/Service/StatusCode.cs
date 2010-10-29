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
    public class StatusCode
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        public static StatusCode Parse(XmlElement statusCode)
        {
            XmlNamespaceManager nsmngr = new XmlNamespaceManager(statusCode.OwnerDocument.NameTable);
            nsmngr.AddNamespace("samlp", samlp);

            XmlAttribute statusCodeValue = statusCode.Attributes["Value"];
            if (statusCodeValue == null) throw new SamlException("sampl:StatusCode does not contain a Value attribute");
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
                    throw new SamlException(String.Format("Illegal sampl:StatusCode/@Value content: {0}", statusCodeValue.Value));
            }

            StatusCode subStatus = null;
            XmlElement subStatusCode = (XmlElement) statusCode.SelectSingleNode("samlp:StatusCode", nsmngr);
            if (subStatusCode != null)
            {
                subStatus = Parse(subStatusCode); 
            }
            return new StatusCode(codeValueLocal, codeValueNs, subStatus);
        }

        private String name;
        private String ns;
        private StatusCode subStatus;

        private StatusCode(string name, string ns, StatusCode subStatus)
        {
            this.name = name;
            this.ns = ns;
            this.subStatus = subStatus;
        }

        public String Name
        {
            get
            {
                return name;
            }
        }

        public String Namespace
        {
            get
            {
                return ns;
            }
        }

        public StatusCode SubStatus
        {
            get
            {
                return subStatus;
            }
        }

        public bool IsSuccess
        {
            get
            {
                return ns == samlp && name == "Success";
            }
        }
    }
}
