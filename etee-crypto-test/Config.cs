using NUnit.Framework;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestFixture]
    public class Config
    {
        private static X509Certificate2 AskCertificate(X509KeyUsageFlags flags)
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection nonRep = my.Certificates.Find(X509FindType.FindByKeyUsage, flags, true);
                return X509Certificate2UI.SelectFromCollection(nonRep, "Select your cert", "Select the cert you want to used to sign the msg", X509SelectionFlag.SingleSelection, IntPtr.Zero)[0];
            }
            finally
            {
                my.Close();
            }
        }

        [Test(Description="Prepares your platform for tests"), Explicit]
        public void SetUp()
        {
            X509Certificate2 testCA = new X509Certificate2("../../imports/CA.cer");
            X509Certificate2 testCA2 = new X509Certificate2("../../imports/CA2.cer");

            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (!store.Certificates.Contains(testCA))
                {
                    store.Add(testCA);
                }
                if (!store.Certificates.Contains(testCA2))
                {
                    store.Add(testCA2);
                }
            }
            finally
            {
                store.Close();
            }

            //ask the sender
            X509Certificate2 authCert = AskCertificate(X509KeyUsageFlags.DigitalSignature);
            File.WriteAllText("authCertTumb.txt", authCert.Thumbprint);
            if (!DotNetUtilities.FromX509Certificate(authCert).GetKeyUsage()[1])
            {
                X509Certificate2 signCert = AskCertificate(X509KeyUsageFlags.NonRepudiation);
                File.WriteAllText("signCertTumb.txt", signCert.Thumbprint);
            }
            else
            {
                File.Delete("signCertTumb.txt");
            }
        }

        [Test(Description = "Cleans up any test config on your platform"), Explicit]
        public void CleanUp()
        {
            X509Certificate2 testCA = new X509Certificate2("../../imports/CA.cer");
            X509Certificate2 testCA2 = new X509Certificate2("../../imports/CA2.cer");

            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (store.Certificates.Contains(testCA))
                {
                    store.Remove(testCA);
                }
                if (store.Certificates.Contains(testCA2))
                {
                    store.Remove(testCA2);
                }
            }
            finally
            {
                store.Close();
            }
        }
    }
}
