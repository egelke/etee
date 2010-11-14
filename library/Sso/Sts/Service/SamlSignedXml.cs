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
using System.Security.Cryptography.Xml;

namespace Siemens.EHealth.Client.Sso.Sts.Service
{
    internal class SamlSignedXml : SignedXml
    {
        public SamlSignedXml(XmlDocument doc)
            : base(doc)
        {

        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement elementById = base.GetIdElement(document, idValue);
            if (elementById != null)
            {
                return elementById;
            }
            return elementById = document.SelectSingleNode("//*[@RequestID=\"" + idValue + "\"]") as XmlElement;
        }

    }
}
