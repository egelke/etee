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
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    //[TestClass]
    public class Assembly
    {
        private static Process webdev;

        //[AssemblyInitialize]
        public static void Init()
        {
            X509Store store;

            store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                LoadCert(store, "CA.cer");
                LoadCert(store, "trustedRoot\\cacert.pem");
            }
            finally
            {
                store.Close();
            }


            store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                LoadCert(store, "interCA.cer");
                LoadCert(store, "trustedRoot\\int\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_overlap\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_overlap2\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_revoked\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_sign\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_usageBase\\cacert.pem");
                LoadCert(store, "trustedRoot\\int_usageKey\\cacert.pem");
                LoadCert(store, "untrustedRoot\\int\\cacert.pem");
            }
            finally
            {
                store.Close();
            }

            webdev = Process.Start(@"C:\Program Files\Common Files\microsoft shared\DevServer\10.0\WebDev.WebServer40.exe", "/port:8181 /path:\"" + System.Environment.CurrentDirectory + "\"");
            Thread.Sleep(5000);
        }

        //[AssemblyCleanup]
        public static void Treardown()
        {
            webdev.Kill();
        }

        private static void LoadCert(X509Store store, String certPath)
        {
            X509Certificate2 cert = new X509Certificate2(certPath);
            X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (found.Count == 0)
            {
                store.Add(cert);
            }
        }
    }
}
