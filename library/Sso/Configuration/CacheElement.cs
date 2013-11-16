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
using System.Configuration;
using System.Xml;

namespace Egelke.EHealth.Client.Sso.Configuration
{
    public class CacheElement : ConfigurationElement
    {
        private XmlDocument content;

        [ConfigurationProperty("type", DefaultValue = "Egelke.EHealth.Client.Sso.MemorySessionCache")]
        public String Type
        {
            get
            {
                return (String)base["type"];
            }
            set
            {
                base["type"] = value;
            }
        }

        public XmlDocument Content
        {
            get
            {
                return content;
            }
        }

        protected override bool OnDeserializeUnrecognizedElement(string elementName, XmlReader reader)
        {
            if (content != null)
            {
                throw new ConfigurationErrorsException("Only one child element is allowed: " + elementName);
            }
            content = new XmlDocument();
            content.Load(reader);
            return true;
        }

    }
}
