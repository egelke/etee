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
using System.ComponentModel;

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public class KnownRecipient : Recipient
    {
        
        public String Type
        {
            get
            {
                return (String)this["Type"];
            }
            set
            {
                this["Type"] = value;
            }
        }


        public String Id
        {
            get
            {
                return (String)this["Id"];
            }
            set
            {
                this["Id"] = value;
            }
        }

        public String Application
        {
            get
            {
                return (String)this["Application"];
            }
            set
            {
                this["Application"] = value;
            }
        }

        public EncryptionToken Token
        {
            get
            {
                return (EncryptionToken)this["Token"];
            }
            set
            {
                this["Token"] = value;
            }
        }

        public KnownRecipient()
            : base("Known")
        {

        }

        public KnownRecipient(String type, String id)
            : this()
        {
            this["Type"] = type;
            this["Id"] = id;
        }

        public KnownRecipient(String type, String id, String application)
            : this(type, id)
        {
            this["Application"] = application;
        }

        public KnownRecipient(EncryptionToken token)
            : this()
        {
            this["Token"] = token;
        }

        public KnownRecipient(EncryptionToken token, String type, String id)
            : this(type, id)
        {
            this["Token"] = token;
        }

        public KnownRecipient(EncryptionToken token, String type, String id, String application)
            : this(type, id, application)
        {
            this["Token"] = token;
        }
    }
}
