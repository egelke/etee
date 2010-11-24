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
using System.Text;
using System.Security.Cryptography;

namespace Siemens.EHealth.Etee.Crypto.Configuration
{
    internal class SealActiveConfig
    {


        public SealActiveConfig()
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public SignatureAlgorithm SignatureAlgorithm
        {
            get
            {
                //RSASSA-PSS/SHA256
                return new SignatureAlgorithm(new Oid("2.16.840.1.101.3.4.2.1", "SHA256"), new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS"));
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public Oid EncryptionAlgorithm
        {
            get
            {
                return new Oid("2.16.840.1.101.3.4.1.2", "AES128");
            }
        }
    }
}
