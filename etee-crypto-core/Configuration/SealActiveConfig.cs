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
using Org.BouncyCastle.Asn1.Pkcs;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    internal class SealActiveConfig
    {
        private static Oid AES128 = new Oid("2.16.840.1.101.3.4.1.2", "AES128");
        private static Oid SHA256 = new Oid("2.16.840.1.101.3.4.2.1", "SHA256");
        private static Oid RSASSAPSS = new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS");
        private static Oid RSA = new Oid("1.2.840.113549.1.1.1", "RSA");
        private static Oid SHA256WITHRSA = new Oid("1.2.840.113549.1.1.11", "sha256WithRSA");
        private static Oid SHA256WITHRSAANDMGF1 = new Oid("1.2.840.113549.1.1.10", "sha256WithRsaAndMgf1");

        private static SignatureAlgorithm SHA256WITHRSAALG = new SignatureAlgorithm(SHA256WITHRSA, SHA256, RSA);
        private static SignatureAlgorithm SHA256WITHRSAANDMGF1ALG = new SignatureAlgorithm(SHA256WITHRSAANDMGF1, SHA256, RSASSAPSS);

        public SealActiveConfig()
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public SignatureAlgorithm NativeSignatureAlgorithm
        {
            get
            {
                return SHA256WITHRSAANDMGF1ALG;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public SignatureAlgorithm WindowsSignatureAlgorithm
        {
            get
            {
                return SHA256WITHRSAALG;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        public Oid EncryptionAlgorithm
        {
            get
            {
                return AES128;
            }
        }
    }
}
