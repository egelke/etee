/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.Text;
using System.Security.Cryptography;
using System.Collections.ObjectModel;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    internal class UnsealActiveConfig
    {
        private ReadOnlyCollection<Oid> keyEncryptionAlgorithms;
        private ReadOnlyCollection<SignatureAlgorithm> signatureAlgorithms;
        private ReadOnlyCollection<Oid> encryptionAlgorithms;
        private int[] signatureKeyUsages;


        public UnsealActiveConfig()
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public int MinimumSignatureKeySize
        {
            get
            {
                return 1024; //for eID
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public EncryptionKeySizeActiveConfig MinimumEncryptionKeySize
        {
            get
            {
                return new EncryptionKeySizeActiveConfig();
            }
        }

        public int[] SignatureKeyUsages
        {
            get
            {
                if (signatureKeyUsages == null)
                {
                    signatureKeyUsages = new int[] { 1 }; //non repudiation;
                }
                return signatureKeyUsages;
            }
            internal set
            {
                signatureKeyUsages = value;
            }
        }

        public ReadOnlyCollection<SignatureAlgorithm> SignatureAlgorithms
        {
            get
            {
                if (signatureAlgorithms == null)
                {
                    signatureAlgorithms = new ReadOnlyCollection<SignatureAlgorithm>(new SignatureAlgorithm[] { 
                        new SignatureAlgorithm(new Oid("2.16.840.1.101.3.4.2.1", "SHA256"), new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS")), 
                        new SignatureAlgorithm(new Oid("2.16.840.1.101.3.4.2.1", "SHA256"), new Oid("1.2.840.113549.1.1.1", "RSA")) 
                    });
                }
                return signatureAlgorithms;
            }
        }

        public ReadOnlyCollection<Oid> EncryptionAlgorithms
        {
            get
            {
                if (encryptionAlgorithms == null)
                {
                    encryptionAlgorithms = new ReadOnlyCollection<Oid>(new Oid[] { 
                        new Oid("2.16.840.1.101.3.4.1.2", "AES128") 
                    });
                }
                return encryptionAlgorithms;
            }
        }

        public ReadOnlyCollection<Oid> KeyEncryptionAlgorithms
        {
            get
            {
                if (keyEncryptionAlgorithms == null)
                {
                    keyEncryptionAlgorithms = new ReadOnlyCollection<Oid>(new Oid[] { 
                        new Oid("1.2.840.113549.1.1.1","rsa"), 
                        new Oid("2.16.840.1.101.3.4.1.5", "aes128wrap") 
                    });
                }
                return keyEncryptionAlgorithms;
            }
        }
    }
}
