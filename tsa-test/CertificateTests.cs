using System;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Linq;
using System.IO;
using Org.BouncyCastle.Asn1;
using System.Runtime.InteropServices;

namespace Egelke.EHealth.Client.Pki.Test
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
            Chain chain = cert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocsps, true, new TimeSpan(0, 1, 0));

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
        CertificateList rootCaCrl;
        BasicOcspResponse leafOcsp;
        BasicOcspResponse leafOcsp2;

        [SetUp]
        public void Setup()
        {
            leafCert = new X509Certificate2("files/eid79021802145.crt");
            intCaCert = new X509Certificate2("files/Citizen201204.crt");
            
            intCaCrl = CertificateList.GetInstance(File.ReadAllBytes("files/Citizen201204.crl"));
            rootCaCrl = CertificateList.GetInstance(File.ReadAllBytes("files/rootca2.crl"));
            leafOcsp = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes("files/eid79021802145.ocsp")));
            leafOcsp2 = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes("files/eid79021802145-2.ocsp")));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: complete
         * Time: little before revocation info
         */
        [Test]
        public void HistoricalNoStore1()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: complete
         * Time: just after revocation info (within skewness)
         */
        [Test]
        public void HistoricalNoStore2()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 14, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: only historical
         * Time: within max delay
         */
        [Test]
        public void HistoricalNoStore3()
        {
            DateTime time = DateTime.UtcNow.AddMinutes(-50);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(3, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }
        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: only historical
         * Time: within limit of delay with time skew
         */
        [Test]
        public void HistoricalNoStore4()
        {
            DateTime time = DateTime.UtcNow.AddMinutes(-60.5);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(3, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: fail
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: wrong period
         * Time: in past, but after provided revocation info
         */
        [Test]
        public void HistoricalNoStore5()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 20, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.RevocationStatusUnknown));
            Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.RevocationStatusUnknown));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: additional
         * Time: little before revocation info
         */
        [Test]
        public void HistoricalNoStore6()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp, leafOcsp2 });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: additional
         * Time: just after revocation info (within skewness)
         */
        [Test]
        public void HistoricalNoStore7()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 14, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp, leafOcsp2 });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: additional, reverse order
         * Time: little before revocation info
         */
        [Test]
        public void HistoricalNoStore8()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp2, leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(2, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: empty
         * Time: now
         */
        [Test]
        public void HistoricalNoStore9()
        {
            if (DateTime.UtcNow > new DateTime(2017, 1, 1)) Assert.Inconclusive("The cert will be revoked around this time");

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

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
         * Provided revocation info: partial (only revocation info of end certificate; both OCSP and CRL)
         * Time: revocation info
         */
        [Test]
        public void HistoricalNoStore10()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 0, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

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
         * Provided revocation info: complete
         * Time: long before the revocation info
         */
        [Test]
        public void NormalNoStore1()
        {
            DateTime time = new DateTime(2013, 1, 1, 12, 0, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps);

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: complete
         * Time: just after revocation info (within skewness)
         */
        [Test]
        public void NormalNoStore2()
        {
            DateTime time = new DateTime(2014, 3, 5, 18, 14, 0, DateTimeKind.Utc);

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { intCaCrl, rootCaCrl });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { leafOcsp });
            Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps);

            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: empty
         * Time: now
         */
        [Test]
        public void NormalNoStore3()
        {
            if (DateTime.UtcNow > new DateTime(2017, 6, 1)) Assert.Inconclusive("The cert is expired, so the OCSP may not respond any more");

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps);

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, chain.ChainElements.Count);
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: empty
         * Time: Time travel to -1 minute
         */
        [Test]
        public void NormalNoStore4()
        {
            DateTime orgNow = DateTime.UtcNow;
            if (DateTime.UtcNow > new DateTime(2017, 6, 1)) Assert.Inconclusive("The cert is expired, so the OCSP may not respond any more");

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();

            //turn back the time 3 minutes
            SYSTEMTIME stime = new SYSTEMTIME();
            GetSystemTime(ref stime);
            if (stime.wMinute < 5) Assert.Inconclusive("Can't run the test now, wait until at least 5 after the hour");
            stime.wMinute = (ushort)(stime.wMinute - 1);
            if (!SetSystemTime(ref stime)) Assert.Inconclusive("Time change failed {0}", Marshal.GetLastWin32Error());
            if ((orgNow - DateTime.UtcNow).TotalSeconds < 50) Assert.Inconclusive("time change not visible {2}: {0} vs {1}", orgNow, DateTime.UtcNow, orgNow - DateTime.UtcNow);
            
            //do the test
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps);
            if ((orgNow - DateTime.UtcNow).TotalSeconds < 50) Assert.Inconclusive("time change reverted during test");

            //forward the time back 3 minutes
            GetSystemTime(ref stime);
            stime.wMinute = (ushort)(stime.wMinute + 1);
            SetSystemTime(ref stime);

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
         * Provided revocation info: empty
         * Time: Time travel to +1 minute
         */
        [Test]
        public void NormalNoStore5()
        {
            DateTime orgNow = DateTime.UtcNow;
            if (DateTime.UtcNow > new DateTime(2017, 6, 1)) Assert.Inconclusive("The cert is expired, so the OCSP may not respond any more");

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();

            //go forward in time 3 minutes
            SYSTEMTIME stime = new SYSTEMTIME();
            GetSystemTime(ref stime);
            if (stime.wMinute > 55) Assert.Inconclusive("Can't run the test now, wait until at least 5 after the hour");
            stime.wMinute = (ushort)(stime.wMinute + 1);
            if (!SetSystemTime(ref stime)) Assert.Inconclusive("Time change failed {0}", Marshal.GetLastWin32Error());
            if ((DateTime.UtcNow - orgNow) < new TimeSpan(0, 0, 50)) Assert.Inconclusive("time change not visible {2}: {0} vs {1}", orgNow, DateTime.UtcNow, DateTime.UtcNow - orgNow);
            

            //do the test
            Chain chain = leafCert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps);
            if ((DateTime.UtcNow - orgNow) < new TimeSpan(0, 0, 50)) Assert.Inconclusive("time change reverted during test");

            //undo go forward in time 3 minutes
            GetSystemTime(ref stime);
            stime.wMinute = (ushort)(stime.wMinute - 1);
            SetSystemTime(ref stime);

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        /*
         * Test: Success
         * Cert status: the certificate is revoked
         * Provided revocation info: none
         * Time: before revocation
         */
       [Test]
       public void NormalNoStore6()
       {
           DateTime time = new DateTime(2014, 03, 11, 12, 0, 0, DateTimeKind.Utc);

           var cert = new X509Certificate2("files/revoked.crt");
           IList<CertificateList> crls = new List<CertificateList>();
           IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
           Chain chain = cert.BuildChain(time, null, ref crls, ref ocps);

           Assert.AreEqual(1, crls.Count);
           Assert.AreEqual(1, ocps.Count);
           Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
       }

        /*
         * Test: Fail not yet valid
         * Cert status: not yet valid, leaf only (check stops there)
         * Provided revocation info: none
         * Time: before cert validation
         */
       [Test]
       public void NormalNoStore7()
       {
           DateTime time = new DateTime(2012, 1, 1, 12, 0, 0, DateTimeKind.Utc);

           IList<CertificateList> crls = new List<CertificateList>();
           IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
           Chain chain = leafCert.BuildChain(time, null, ref crls, ref ocps);

           Assert.AreEqual(1, crls.Count);
           Assert.AreEqual(1, ocps.Count);
           Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
           Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
           Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
       }

        /*
         * Test: Fail expired
         * Cert status: the certificate is expired
         * Provided revocation info: none
         * Time: after expiration
         */
       [Test]
       public void NormalNoStore8()
       {
           DateTime time = new DateTime(2014, 03, 15, 12, 0, 0, DateTimeKind.Utc);

           var cert = new X509Certificate2("files/expired.crt");
           IList<CertificateList> crls = new List<CertificateList>();
           IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
           Chain chain = cert.BuildChain(time, null, ref crls, ref ocps);

           Assert.AreEqual(1, crls.Count);
           Assert.AreEqual(1, ocps.Count);
           Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
           Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.NotTimeValid));
           Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
       }

        /*
         * Test: Fail suspended
         * Cert status: the certificate is suspended
         * Provided revocation info: none
         * Time: fixed point
         */
       [Test]
       public void NormalNoStore9()
       {
           DateTime time = new DateTime(2014, 03, 15, 12, 0, 0, DateTimeKind.Utc);

           var cert = new X509Certificate2("files/suspended.crt");
           IList<CertificateList> crls = new List<CertificateList>();
           IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
           Chain chain = cert.BuildChain(time, null, ref crls, ref ocps);

           Assert.AreEqual(1, crls.Count);
           Assert.AreEqual(1, ocps.Count);
           Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.Revoked));
           Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.Revoked));
           Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
       }

        /*
         * Test: Fail revoked
         * Cert status: the certificate is revoked
         * Provided revocation info: none
         * Time: fixed point
         */
        [Test]
       public void NormalNoStore10()
       {
           DateTime time = new DateTime(2014, 03, 15, 12, 0, 0, DateTimeKind.Utc);

           var cert = new X509Certificate2("files/revoked.crt");
           IList<CertificateList> crls = new List<CertificateList>();
           IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
           Chain chain = cert.BuildChain(time, null, ref crls, ref ocps);

           Assert.AreEqual(1, crls.Count);
           Assert.AreEqual(1, ocps.Count);
           Assert.AreEqual(1, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.Revoked));
           Assert.AreEqual(1, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status == X509ChainStatusFlags.Revoked));
           Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
           Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
       }

        /*
         * Test: Success
         * Cert status: OK (not expired, not revoked/suspended)
         * Provided revocation info: none
         * Signing time: now
         */
        [Test]
        public void HistorialStore()
        {
            DateTime time = DateTime.UtcNow;
            if (time > new DateTime(2019, 3, 19)) Assert.Inconclusive("The cert is (or will very soon be) expired");

            var cert = new X509Certificate2("files/foreigner.crt");
            var caCert = new X509Certificate2("files/foreigner_ca.crt");
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            X509Certificate2Collection inter = new X509Certificate2Collection(caCert);
            Chain chain = cert.BuildChain(time, inter, ref crls, ref ocps, true, new TimeSpan(1, 0, 0));

            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocps.Count);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[0].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[1].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, chain.ChainElements[2].ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        [DllImport("Kernel32.dll")]
        private extern static void GetSystemTime(ref SYSTEMTIME lpSystemTime);

        [DllImport("Kernel32.dll")]
        private extern static bool SetSystemTime(ref SYSTEMTIME lpSystemTime);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SYSTEMTIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;
        }
    }
}
