using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using Org.BouncyCastle.Tls;

namespace Egelke.EHealth.Client.Security
{
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

        public X509Certificate2 Certificate { get; set; }

        internal CustomSecurityClientCredential() { }

        internal CustomSecurityClientCredential(CustomSecurityClientCredential other)
        {
            Certificate = other.Certificate;
        }

        public void SetCertificate(string subjectName, StoreLocation storeLocation, StoreName storeName)
        {
            if (subjectName == null)
            {
                throw new ArgumentNullException(nameof(subjectName));
            }

            SetCertificate(storeLocation, storeName, X509FindType.FindBySubjectDistinguishedName, subjectName);
        }

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
