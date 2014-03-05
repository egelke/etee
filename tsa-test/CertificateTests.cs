using System;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Tsa;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Linq;
using System.IO;
using Org.BouncyCastle.Asn1;

namespace Egelke.EHealth.Client.TsaTest
{
    [TestFixture]
    public class CertificateTests
    {
        private static X509Certificate2 AskCertificate(X509KeyUsageFlags flags)
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection nonRep = my.Certificates.Find(X509FindType.FindByKeyUsage, flags, true);
                return X509Certificate2UI.SelectFromCollection(nonRep, "Select your cert", "Select the cert you want to used to sign the msg", X509SelectionFlag.SingleSelection)[0];
            }
            finally
            {
                my.Close();
            }
        }

        //[Test]
        public void SaveFromSelected()
        {
            X509Certificate2 cert = AskCertificate(X509KeyUsageFlags.DigitalSignature);

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain chain = cert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocsps, DateTime.UtcNow, true, new TimeSpan(0, 1, 0));

            int i = 1;
            foreach (ChainElement element in chain.ChainElements)
            {
                File.WriteAllBytes("cert" + i++ + ".crt", element.Certificate.GetRawCertData());
            }
            i = 1;
            foreach(CertificateList crl in crls)
            {
                File.WriteAllBytes("crl" + i++ + ".crl", crl.GetEncoded());
            }
            i = 1;
            foreach (BasicOcspResponse ocsp in ocsps)
            {
                File.WriteAllBytes("ocsp" + i++ + ".ocsp", ocsp.GetEncoded());
            }
        }

        X509Certificate2 leafCert;
        X509Certificate2 intCaCert;
        CertificateList intCaCrl;
        BasicOcspResponse leafOcsp;
        BasicOcspResponse leafOcsp2;

        [SetUp]
        public void Setup()
        {
            leafCert = new X509Certificate2("files/eid79021802145.crt");
            intCaCert = new X509Certificate2("files/Citizen201204.crt");
            intCaCrl = CertificateList.GetInstance(File.ReadAllBytes("files/Citizen201204.crl"));
            leafOcsp = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes("files/eid79021802145.ocsp")));
            leafOcsp2 = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes("files/eid79021802145-2.ocsp")));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: Yes
         * Provided revocation info: complete
         * Intermedate CA location: Win store
         * Trust signing time: yes (i.e. trusted time = signing time)
         */
        [Test]
        public void Success1()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, time, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: Yes
         * Provided revocation info: additional
         * Intermedate CA location: Win store
         * Trust signing time: yes (i.e. trusted time = signing time)
         */
        [Test]
        public void Success2()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp, leafOcsp2 });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, time, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: false
         * Provided revocation info: complete
         * Intermedate CA location: Win store
         * Trust signing time: yes (i.e. trusted time = signing time)
         */
        [Test]
        public void Success3()
        {
            DateTime time = new DateTime(2013, 1, 1, 12, 0, 0); //This is before the OCSP Responder, on purpose

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, time);

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: true
         * Provided revocation info: empty
         * Intermedate CA location: Win store
         * Trust signing time: yes (i.e. trusted time = signing time)
         */
        [Test]
        public void Success4()
        {
            if (DateTime.UtcNow > new DateTime(2017, 1, 1)) Assert.Inconclusive("The cert will be revoked around this time");

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps, DateTime.UtcNow, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: false
         * Provided revocation info: empty
         * Intermedate CA location: Win store
         * Trust signing time: no (i.e. trusted time = more recent then signing time)
         */
        [Test]
        public void Success5()
        {
            if (DateTime.UtcNow > new DateTime(2017, 6, 1)) Assert.Inconclusive("The cert is expired, so the OCSP may not respond any more");
            
            DateTime time = new DateTime(2013, 1, 1, 12, 0, 0);
            DateTime trustedTime = new DateTime(2014, 1, 1, 12, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps, trustedTime);

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: true
         * Provided revocation info: partial (only revocation info at signing time)
         * Intermedate CA location: Win store
         * Trust signing time: No (i.e. trusted time = now)
         */
        [Test]
        public void Success6()
        {
            if (DateTime.UtcNow > new DateTime(2017, 1, 1)) Assert.Inconclusive("The cert will be revoked around this time");

            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, DateTime.UtcNow, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count); //will become 2 in a few days...
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: true
         * Provided revocation info: full
         * Intermedate CA location: Win store
         * Trust signing time: No (i.e. trusted time = now)
         */
        [Test]
        public void Success7()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0);
            DateTime trustedTime = new DateTime(2014, 3, 5, 20, 30, 0);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp, leafOcsp2 });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, trustedTime, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Fail historical suspended
         * Cert status: not yet valid, leaf only (check stops there)
         * Check historical supspened: false
         * Provided revocation info: none
         * Trust signing time: no (i.e. trusted time = now)
         */
        [Test]
        public void FailNotYetValid()
        {
            DateTime time = new DateTime(2012, 1, 1, 12, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, DateTime.UtcNow);

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
            Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Fail historical suspended
         * Cert status: OK (not expired, not revoked/suspended)
         * Check historical supspened: true
         * Provided revocation info: complete
         * Trust signing time: yes (i.e. trusted time = signing time)
         */
        [Test]
        public void FailHistoricalSuspended()
        {
            DateTime time = new DateTime(2013, 1, 1, 12, 0, 0);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, time, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.CtlNotTimeValid));
            Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.CtlNotTimeValid));
            Assert.AreEqual(1, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.CtlNotTimeValid));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }
    }
}
