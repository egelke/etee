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
using System.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Client.Sso.Configuration
{
    public class SessionCertificateElement : ConfigurationElement
    {
        [ConfigurationProperty("selfSigned", DefaultValue = false)]
        public bool SelfSigned
        {
            get
            {
                return (bool)base["selfSigned"];
            }
            set
            {
                base["selfSigned"] = value;
            }
        }

        [StringValidator(MinLength = 0), ConfigurationProperty("findValue", DefaultValue = "")]
        public string FindValue
        {
            get
            {
                return (string)base["findValue"];
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    value = string.Empty;
                }
                base["findValue"] = value;
            }
        }

        [ConfigurationProperty("storeLocation", DefaultValue = StoreLocation.CurrentUser)]
        public StoreLocation StoreLocation
        {
            get
            {
                return (StoreLocation)base["storeLocation"];
            }
            set
            {
                base["storeLocation"] = value;
            }
        }

        [ConfigurationProperty("storeName", DefaultValue = StoreName.My)]
        public StoreName StoreName
        {
            get
            {
                return (StoreName)base["storeName"];
            }
            set
            {
                base["storeName"] = value;
            }
        }

        [ConfigurationProperty("x509FindType", DefaultValue = X509FindType.FindBySubjectDistinguishedName)]
        public X509FindType X509FindType
        {
            get
            {
                return (X509FindType)base["x509FindType"];
            }
            set
            {
                base["x509FindType"] = value;
            }
        }

    }
}
