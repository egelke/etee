using Egelke.Fedict.Eid;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace eid_test
{
    
    
    /// <summary>
    ///This is a test class for EidWrapperTest and is intended
    ///to contain all EidWrapperTest Unit Tests
    ///</summary>
    [TestClass()]
    public class EidWrapperTest
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


        /// <summary>
        ///A test for ReadCertificate
        ///</summary>
        [TestMethod()]
        public void ReadCertificateTest()
        {
            String[] readers = EidReader.Readers;
            if (readers.Length != 1) Assert.Inconclusive("Can't select a reader, " + readers.Length + " present: " + String.Join(", ", readers));

            EidReader target = new EidReader(readers[0]);
            using (target)
            {
                target.CardAction += new EventHandler<DeviceEventArgs>(target_CardAction);
                target.Connect();

                X509Certificate2 auth = target.ReadCertificate(Certificate.Authentication);
                X509Certificate2 sign = target.ReadCertificate(Certificate.Signature);
                X509Certificate2 ca = target.ReadCertificate(Certificate.CA);
                X509Certificate2 root = target.ReadCertificate(Certificate.Root);

                Assert.AreNotEqual(auth.Subject, sign.Subject);
                Assert.AreEqual(sign.Issuer, ca.Subject);
                Assert.AreEqual(auth.Issuer, ca.Subject);
                Assert.AreEqual(ca.Issuer, root.Subject);
                Assert.AreEqual(root.Issuer, root.Subject);
            }
        }

        EventWaitHandle waitChange = new EventWaitHandle(false, EventResetMode.AutoReset);

        [TestMethod()]
        public void CardChangeTest()
        {
            EidReader target = new EidReader("ACS CCID USB Reader 0");
            using (target)
            {
                target.CardAction += new EventHandler<DeviceEventArgs>(target_CardAction);
                target.ReaderAction += new EventHandler<DeviceEventArgs>(target_ReaderAction);

                //Wait for 2 events...
                waitChange.WaitOne(new TimeSpan(0, 1, 0));
                waitChange.WaitOne(new TimeSpan(0, 1, 0));
            }
        }

        void target_ReaderAction(object sender, DeviceEventArgs e)
        {
            System.Console.Out.WriteLine(String.Format("Reader {2} status changed from {0} to {1}", e.PreviousState, e.NewState, e.DeviceName));
            waitChange.Set();
        }

        void target_CardAction(object sender, DeviceEventArgs e)
        {
            System.Console.Out.WriteLine(String.Format("Card {2} status changed from {0} to {1}", e.PreviousState, e.NewState, e.DeviceName));
            waitChange.Set();
        }
    }
}
