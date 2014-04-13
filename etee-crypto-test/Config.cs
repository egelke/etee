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
