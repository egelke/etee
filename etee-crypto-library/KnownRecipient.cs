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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace Egelke.EHealth.Etee.Crypto.Library
{
    public class KnownRecipient : Recipient
    {
       
        public class IdType
        {
            public String Value { get; set; }

            public String Type { get; set; }

            public IdType(String type, String value)
            {
                this.Value = value;
                this.Type = type;
            }

        }

        public IdType Id { get ; set;}

        public String Application {get; set;}

        private EncryptionToken token;

        public EncryptionToken Token { 
            get { return token; }
            set
            {
                token = value;
                TokenRetreivalTime = DateTime.UtcNow;
            }
        }

        public DateTime TokenRetreivalTime { get; private set; }

        public KnownRecipient(IdType id)
        {
            Id = id;
        }

        public KnownRecipient(IdType id, String application)
            : this(id)
        {
            this.Application = application;
        }

        public KnownRecipient(EncryptionToken token)
        {
            this.Token = token;
            TokenRetreivalTime = DateTime.UtcNow;
            //TODO: extract Id & application from token
        }
    }
}
