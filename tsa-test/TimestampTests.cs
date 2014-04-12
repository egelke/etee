using Egelke.EHealth.Client.Pki;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestFixture]
    public class TimestampTests
    {
        /*
         * Test: Success
         * TS status: OK
         * Provided revocation info: none
         * For arbitratition: no
         */
        [Test]
        public void Fedict1()
        {
            if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(ref crls, ref ocps);
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 12, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        /*
         * Test: Success
         * TS status: OK
         * Provided revocation info: all
         * For arbitratition: no
         */
        [Test]
        public void Fedict2()
        {
            CertificateList crl1  = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(ref crls, ref ocps);
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 12, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        /*
         * Test: Success
         * TS status: OK
         * Provided revocation info: all
         * For arbitratition: yes, with trusted time
         */
        [Test]
        public void Fedict3()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(ref crls, ref ocps, new DateTime(2014, 3, 16, 11, 0, 0, DateTimeKind.Utc));
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 12, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        /*
         * Test: Success
         * TS status: OK
         * Provided revocation info: partial
         * For arbitratition: yes, with current time
         */
        [Test]
        public void Fedict4()
        {
            if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");
            if (DateTime.UtcNow > new DateTime(2014, 4, 15, 15, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The CRL-1 has expired, the crls count should become 3");
            if (DateTime.UtcNow > new DateTime(2014, 7, 31, 11, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The CRL-2 has expired, the crls count should become 4");

            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(ref crls, ref ocps, null);
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 12, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [Test]
        public void EHealth1()
        {
            if (DateTime.UtcNow > new DateTime(2016, 3, 17, 11, 25, 11, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            TimeStampToken tst = File.ReadAllBytes("files/ehTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate();
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 48, 128), ts.Time);
            Assert.AreEqual(new DateTime(2016, 3, 17, 11, 25, 11), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }
    }
}
