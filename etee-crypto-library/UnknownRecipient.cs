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

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public class UnknownRecipient : Recipient
    {
        public String Namespace
        {
            get
            {
                return (String)this["Namespace"];
            }
            set
            {
                this["Namespace"] = value;
            }
        }

        public String Name
        {
            get
            {
                return (String)this["Name"];
            }
            set
            {
                this["Name"] = value;
            }
        }

        public String Value
        {
            get
            {
                return (String)this["Value"];
            }
            set
            {
                this["Value"] = value;
            }
        }

        public UnknownRecipient()
            : base("Unknown")
        {

        }

        public UnknownRecipient(String ns, String name, String value)
            : this()
        {
            this["Namespace"] = ns;
            this["Name"] = name;
            this["Value"] = value;
        }
    }
}
