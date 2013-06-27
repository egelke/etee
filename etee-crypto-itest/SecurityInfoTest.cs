using Siemens.EHealth.Etee.Crypto.Library;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;

namespace Siemens.EHealth.Etee.ITest
{
    
    
    /// <summary>
    ///This is a test class for SecurityInfoTest and is intended
    ///to contain all SecurityInfoTest Unit Tests
    ///</summary>
    [TestClass()]
    public class SecurityInfoTest
    {


        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        
        [TestMethod()]
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

        [TestMethod()]
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
