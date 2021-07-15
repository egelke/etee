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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class Config
    {
        private static bool doSetup = true;

        private static bool doCleanup = false;

        [AssemblyInitialize]
        [TestCategory("Config")]
        public static void SetUp(TestContext ctx)
        {
            if (!doSetup) return;

            X509Certificate2 testCA = new X509Certificate2("imports/CA.cer");
            X509Certificate2 testCA2 = new X509Certificate2("imports/CA2.cer");
            X509Certificate2 testCA3 = new X509Certificate2("imports/specimenCa.cer");

            //X509Certificate2 testIntCA = new X509Certificate2(GetAbsoluteTestFilePath("imports/specimenCitizenCa.cer"));

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
                if (!store.Certificates.Contains(testCA3))
                {
                    store.Add(testCA3);
                }
            }
            finally
            {
                store.Close();
            }
        }

        [AssemblyCleanup]
        [TestCategory("Config")]
        public static void CleanUp()
        {
            if (!doCleanup) return;

            X509Certificate2 testCA = new X509Certificate2("imports/CA.cer");
            X509Certificate2 testCA2 = new X509Certificate2("imports/CA2.cer");
            X509Certificate2 testCA3 = new X509Certificate2("imports/specimenCa.cer");

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
                if (store.Certificates.Contains(testCA3))
                {
                    store.Remove(testCA3);
                }
            }
            finally
            {
                store.Close();
            }
        }
    }
}
