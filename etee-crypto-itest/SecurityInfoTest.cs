using Siemens.EHealth.Etee.Crypto.Library;
using System;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using NUnit.Framework;

namespace Siemens.EHealth.Etee.ITest
{
    
    
    /// <summary>
    ///This is a test class for SecurityInfoTest and is intended
    ///to contain all SecurityInfoTest Unit Tests
    ///</summary>
    [Test]
    public class SecurityInfoTest
    {
        [Test]
        public void CreateOfHosptialTest()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2 authCert = my.Certificates.Find(X509FindType.FindByThumbprint, "415442ca384c853231e203fafa9a436f33b4043b", false)[0];
            Crypto.Library.ServiceClient.EtkDepotPortTypeClient etkDepot = new Crypto.Library.ServiceClient.EtkDepotPortTypeClient("etk");

            SecurityInfo actual;
            actual = SecurityInfo.Create(authCert, StoreLocation.CurrentUser, etkDepot);

            Assert.IsNotNull(actual.Token);
        }

        [Test]
        public void CreateOfCINTest()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2 authCert = my.Certificates.Find(X509FindType.FindByThumbprint, "f2f3bc3916d635c69820a0351b6a58c37b445451", false)[0];
            Crypto.Library.ServiceClient.EtkDepotPortTypeClient etkDepot = new Crypto.Library.ServiceClient.EtkDepotPortTypeClient("etk");

            SecurityInfo actual;
            actual = SecurityInfo.Create(authCert, StoreLocation.CurrentUser, etkDepot);

            Assert.IsNotNull(actual.Token);
            using (FileStream fs = new FileStream(@"d:\tmp\cin-mcn.etk", FileMode.Create))
            {
                fs.Write(actual.Token.GetEncoded(), 0, actual.Token.GetEncoded().Length);
            }
        }
    }
}
