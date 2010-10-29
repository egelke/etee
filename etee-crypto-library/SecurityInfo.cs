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

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public class SecurityInfo
    {
        public static SecurityInfo SelectSelf()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection findFrom = my.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, true);
            X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(findFrom, "Sender Certificate", "Select your signing certificate", X509SelectionFlag.SingleSelection);
            if (selected.Count == 1)
            {
                return SecurityInfo.Create(selected[0]);
            }
            return null;
        }

        public static SecurityInfo Create(X509Certificate2 authCert)
        {
            return Create(authCert, StoreLocation.CurrentUser);
        }

        public static SecurityInfo CreateSendOnly(X509Certificate2 authCert)
        {
            return new SecurityInfo(authCert, null);
        }


        public static SecurityInfo Create(X509Certificate2 authCert, StoreLocation store)
        {
            X509Store my = new X509Store(StoreName.My, store);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection allEncCerts = my.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.KeyEncipherment, false);
            X509Certificate2Collection encCerts = allEncCerts.Find(X509FindType.FindByIssuerDistinguishedName, authCert.Subject, false);
            if (encCerts.Count != 1) throw new Exception(); //TODO: Improve
            return new SecurityInfo(authCert, encCerts[0]);
        }

        private X509Certificate2 authCert;

        private X509Certificate2 encCert;

        private EncryptionToken etk;

        public SecurityInfo(X509Certificate2 authCert, X509Certificate2 encCert) : 
            this(authCert, encCert, null)
        {

        }

        public SecurityInfo(X509Certificate2 authCert, X509Certificate2 encCert, EncryptionToken etk)
        {
            this.authCert = authCert;
            this.encCert = encCert;
            this.etk = etk;
        }

        public X509Certificate2 AuthenticationCertificate
        {
            get
            {
                return authCert;
            }
        }

        public X509Certificate2 EncryptionCertificate
        {
            get
            {
                return encCert;
            }
        }

        public EncryptionToken Token
        {
            get
            {
                return etk;
            }
            set
            {
                etk = value;
            }
        }

        public bool IsSendOnly
        {
            get
            {
                return encCert == null;
            }
        }
    }
}
