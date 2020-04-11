using Egelke.EHealth.Client.Pki;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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
    [TestClass]
    public class TimestampTests
    {

        [TestMethod]
        public void Fedict_TsInternalTime_GetNewCrl()
        {
            //if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps); //use timestamp time to verify
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.AreEqual(2, ts.CertificateChain.ChainElements.Count, "There should be 2, please remove the resigned Root CA's from your store");
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [TestMethod]
        public async Task Fedict_TsInternalTime_GetNewCrlAsync()
        {
            //if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = await tst.ValidateAsync(crls, ocps); //use timestamp time to verify
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.AreEqual(2, ts.CertificateChain.ChainElements.Count, "There should be 2, please remove the resigned Root CA's from your store");
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [TestMethod]
        public void FedictTs_InternalTime_ProvideCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps);
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            Assert.AreEqual(2, ts.CertificateChain.ChainElements.Count, "There should be 2, please remove the resigned Root CA's from your store");
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [TestMethod]
        public void FedictTs_ProvidedTime_ProvideCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps, new DateTime(2014, 3, 16, 11, 0, 0, DateTimeKind.Utc));
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            Assert.AreEqual(2, ts.CertificateChain.ChainElements.Count, "There should be 2, please remove the resigned Root CA's from your store");
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(2, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [TestMethod]
        public void FedictTs_ProvidedTime_ProvideOutdatedCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps, new DateTime(2019, 1, 5, 13, 34, 12, DateTimeKind.Utc));
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            Assert.AreEqual(2, ts.CertificateChain.ChainElements.Count, "There should be 2, please remove the resigned Root CA's from your store");
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            
            Assert.AreEqual(3, crls.Count);
            Assert.AreEqual(0, ocps.Count);
        }

        [TestMethod, Ignore]
        public void EHealth1()
        {
            //if (DateTime.UtcNow > new DateTime(2016, 3, 17, 11, 25, 11, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            TimeStampToken tst = File.ReadAllBytes("files/ehTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate();
            Assert.AreEqual(new DateTime(2014, 3, 15, 11, 50, 48, 128, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.AreEqual(new DateTime(2016, 3, 17, 10, 25, 11, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }
    }
}
