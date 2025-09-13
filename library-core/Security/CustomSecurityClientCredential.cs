/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using Org.BouncyCastle.Tls;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Own implementation of SecurityClientCredential since the original one is internal in some fameworks.
    /// </summary>
    public class CustomSecurityClientCredential
    {
        private static X509Certificate2 GetCertificateFromStore(StoreName storeName, StoreLocation storeLocation,
            X509FindType findType, object findValue)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(findType, findValue, false);
                if (certs.Count == 1)
                {
                    return new X509Certificate2(certs[0]);
                }

                throw new InvalidOperationException(string.Format("No or multiple certificates found: {0}={1} ", findType, findValue));
            }
        }

        /// <summary>
        /// Direct reference to the certificate to use.
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        internal CustomSecurityClientCredential() { }

        internal CustomSecurityClientCredential(CustomSecurityClientCredential other)
        {
            Certificate = other.Certificate;
        }

        /// <summary>
        /// Obtain the certificate from the provide windows store using subject distinguished name, sets the Certificate property.
        /// </summary>
        /// <param name="subjectName">subject distinguished name to search</param>
        /// <param name="storeLocation">store location to search</param>
        /// <param name="storeName">store name to search</param>
        /// <exception cref="ArgumentNullException">no subject name is provided</exception>
        public void SetCertificate(string subjectName, StoreLocation storeLocation, StoreName storeName)
        {
            if (subjectName == null)
            {
                throw new ArgumentNullException(nameof(subjectName));
            }

            SetCertificate(storeLocation, storeName, X509FindType.FindBySubjectDistinguishedName, subjectName);
        }

        /// <summary>
        /// Obtain the certificate from the provide windows store, sets the Certificate property.
        /// </summary>
        /// <param name="storeLocation">store location to search</param>
        /// <param name="storeName">store name to search</param>
        /// <param name="findType">which field of the certificate-entry to look for</param>
        /// <param name="findValue">value to look for in the requested field</param>
        /// <exception cref="ArgumentNullException">no find value provided</exception>
        /// <seealso cref="X509Certificate2Collection.Find(X509FindType, object, bool)"/>
        public void SetCertificate(StoreLocation storeLocation, StoreName storeName, X509FindType findType, object findValue)
        {
            if (findValue == null)
            {
                throw new ArgumentNullException(nameof (findValue));
            }

            Certificate = GetCertificateFromStore(storeName, storeLocation, findType, findValue);
        }

    }
}
