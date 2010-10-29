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
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Decrypt;

namespace etee_examples2
{
    class Utils
    {
        public static byte[] GetNewSecretKey(out byte[] keyId)
        {
            keyId = null;
            return null;
        }

        public static X509Certificate2 SelfAuth
        {
            get
            {
                return null;
            }
        }

        public static X509Certificate2 SelfEnc
        {
            get
            {
                return null;
            }
        }

        public static void Check(EtkSecurityInformation result)
        {

        }

        public static byte[] ReadFully(String file)
        {
            return null;
        }
    }
}
