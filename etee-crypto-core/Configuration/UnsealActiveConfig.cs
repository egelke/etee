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
using System.Collections.ObjectModel;

namespace Siemens.EHealth.Etee.Crypto.Configuration
{
    internal class UnsealActiveConfig : SealActiveConfig
    {
        private ReadOnlyCollection<Oid> keyEncryptionAlgorithms;


        public UnsealActiveConfig()
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public int MinimuumSignatureKeySize
        {
            get
            {
                return 2048;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public EncryptionKeySizeActiveConfig MinimuumEncryptionKeySize
        {
            get
            {
                return new EncryptionKeySizeActiveConfig();
            }
        }

        public ReadOnlyCollection<Oid> KeyEncryptionAlgorithms
        {
            get
            {
                if (keyEncryptionAlgorithms == null)
                {
                    keyEncryptionAlgorithms = new ReadOnlyCollection<Oid>(new Oid[] { new Oid("rsa"), new Oid("2.16.840.1.101.3.4.1.5", "aes128wrap") });
                }
                return keyEncryptionAlgorithms;
            }
        }
    }
}
