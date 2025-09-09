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
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    /// <summary>
    /// Extend the SignedXml with additional Id elements (saml-p, saml and wss)
    /// </summary>
    public class CustomSignedXml : SignedXml
    {
        /// <summary>
        /// Constructor for an XmlDocument
        /// </summary>
        /// <param name="doc">xml document used to validate or sign</param>
        public CustomSignedXml(XmlDocument doc) : base(doc)
        {

        }

        /// <summary>
        /// Constructor for an XmlElement
        /// </summary>
        /// <param name="el">xml element used to validate or sign</param>
        public CustomSignedXml(XmlElement el) : base(el)
        {

        }

        /// <summary>
        /// Extend element search, first base then use XPath to find alternatives.
        /// </summary>
        /// <remarks>
        /// Supports RequestID (saml-p), AssertionID (saml) and wsu:Id (wss).
        /// </remarks>
        /// <param name="document"></param>
        /// <param name="idValue"></param>
        /// <returns></returns>
        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement found = base.GetIdElement(document, idValue);
            if (found != null) return found;

            //saml request
            found = document.SelectSingleNode("//*[@RequestID=\"" + idValue + "\"]") as XmlElement;
            if (found != null) return found;

            //saml assertion
            found = document.SelectSingleNode("//*[@AssertionID=\"" + idValue + "\"]") as XmlElement;
            if (found != null) return found;

            //wss
            var nsmngr = new XmlNamespaceManager(document.NameTable);
            nsmngr.AddNamespace("wsu", WSS.UTILITY_NS);
            return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmngr) as XmlElement;
        }
    }
}
