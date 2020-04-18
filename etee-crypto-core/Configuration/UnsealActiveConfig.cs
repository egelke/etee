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
        private static Oid SHA256 = new Oid("2.16.840.1.101.3.4.2.1", "SHA256");
        private static Oid SHA512 = new Oid("2.16.840.1.101.3.4.2.3", "SHA512");
        private static Oid RSASSAPSS = new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS");
        private static Oid RSA = new Oid("1.2.840.113549.1.1.1", "RSA");
        private static Oid SHA256WITHRSA = new Oid("1.2.840.113549.1.1.11", "sha256WithRSA");
        private static Oid SHA512WITHRSA = new Oid("1.2.840.113549.1.1.13", "sha512WithRSA");

        private static readonly ReadOnlyCollection<Oid> keyEncryptionAlgorithms;
        private static readonly ReadOnlyCollection<SignatureAlgorithm> signatureAlgorithms;
        private static readonly ReadOnlyCollection<Oid> encryptionAlgorithms;

        static UnsealActiveConfig()
        {
            keyEncryptionAlgorithms = new ReadOnlyCollection<Oid>(new Oid[] {
                new Oid("1.2.840.113549.1.1.1","rsa"),
                new Oid("2.16.840.1.101.3.4.1.5", "aes128wrap"),
                new Oid("2.16.840.1.101.3.4.1.25", "aes192wrap"),
                new Oid("2.16.840.1.101.3.4.1.45", "aes256wrap")
            });
            encryptionAlgorithms = new ReadOnlyCollection<Oid>(new Oid[] {
                new Oid("2.16.840.1.101.3.4.1.2", "AES128"),
                new Oid("2.16.840.1.101.3.4.1.22", "AES192"),
                new Oid("2.16.840.1.101.3.4.1.42", "AES256")
            });
            signatureAlgorithms = new ReadOnlyCollection<SignatureAlgorithm>(new SignatureAlgorithm[] {
                new SignatureAlgorithm(null, SHA256, RSASSAPSS),
                new SignatureAlgorithm(null, SHA512, RSASSAPSS),
                new SignatureAlgorithm(null, SHA256, RSA),
                new SignatureAlgorithm(null, SHA512, RSA),
                new SignatureAlgorithm(null, SHA256, SHA256WITHRSA),
                new SignatureAlgorithm(null, SHA512, SHA512WITHRSA)
            });
        }

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

        public ReadOnlyCollection<SignatureAlgorithm> SignatureAlgorithms
        {
            get => signatureAlgorithms;
        }

        public ReadOnlyCollection<Oid> EncryptionAlgorithms
        {
            get => encryptionAlgorithms;
        }

        public ReadOnlyCollection<Oid> KeyEncryptionAlgorithms
        {
            get => keyEncryptionAlgorithms;
        }
    }
}
