
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
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class TimestampTests : IClassFixture<CTPRootCAFicture>, IClassFixture<QuoVadisFicture>
    {
        public TimestampTests(CTPRootCAFicture ctpcaFicture, QuoVadisFicture quoVadisFicture)
        {
            bool install = true;

            Dictionary<String, bool> ctpca = ctpcaFicture.Verify();
            Dictionary<String, bool> quoVadisCa = quoVadisFicture.Verify();
            if (!install)
            {
                if (!ctpca["Qualified"]) throw new InvalidOperationException("Tests will fail due to missing certipost root qualified ca, switch the install flag in the test code to install");
                if (!quoVadisCa["1 G3"]) throw new InvalidOperationException("Tests will fail due to missing QuoVadis root CA1 G3, switch the install flag in the test code to install");
            }
            else
            {
                ctpcaFicture.Install("Qualified");
                quoVadisFicture.Install("1 G3");
            }
        }

        [Fact]
        public void Fedict_TsInternalTime_GetNewCrl()
        {
            //if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps); //use timestamp time to verify
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.Equal(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                //belgian root CA
                Assert.Equal(1, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 4)
            {
                //belgian resigned CA
                Assert.Equal(3, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else
            {
                Assert.False(true, "The chain should be 4 or 2 long");
            }
        }

        [Fact]
        public async Task Fedict_TsInternalTime_GetNewCrlAsync()
        {
            //if (DateTime.UtcNow > new DateTime(2019, 1, 23, 12, 0, 0, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] {  });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = await tst.ValidateAsync(crls, ocps); //use timestamp time to verify
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.Equal(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                //belgian root CA
                Assert.Equal(1, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 4)
            {
                //belgian resigned CA
                Assert.Equal(3, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else
            {
                Assert.False(true, "The chain should be 4 or 2 long");
            }
        }

        [Fact]
        public void FedictTs_InternalTime_ProvideCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            CertificateList crl3 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs3.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2, crl3 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps);
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.Equal(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                //belgian root CA
                Assert.Equal(1, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 4)
            {
                //belgian resigned CA
                Assert.Equal(3, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else
            {
                Assert.False(true, "The chain should be 4 or 2 long");
            }
        }

        [Fact]
        public void FedictTs_ProvidedTime_ProvideCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            CertificateList crl3 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs3.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2, crl3 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps, new DateTime(2014, 3, 16, 11, 0, 0, DateTimeKind.Utc));
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.Equal(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                //belgian root CA
                Assert.Equal(1, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 4)
            {
                //belgian resigned CA
                Assert.Equal(3, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else
            {
                Assert.False(true, "The chain should be 4 or 2 long");
            }
        }

        [Fact]
        public void FedictTs_ProvidedTime_ProvideOutdatedCrl()
        {
            CertificateList crl1 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs1.crl"));
            CertificateList crl2 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs2.crl"));
            CertificateList crl3 = CertificateList.GetInstance(File.ReadAllBytes("files/fedictTs3.crl"));
            IList<CertificateList> crls = new List<CertificateList>(new CertificateList[] { crl1, crl2 });
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>(new BasicOcspResponse[] { });
            TimeStampToken tst = File.ReadAllBytes("files/fedictTs.ts").ToTimeStampToken();

            Timestamp ts = tst.Validate(crls, ocps, new DateTime(2019, 1, 5, 13, 34, 12, DateTimeKind.Utc));
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 49, DateTimeKind.Utc), ts.Time);
            Assert.Equal(new DateTime(2019, 1, 23, 11, 0, 0, DateTimeKind.Utc), ts.RenewalTime);
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                //belgian root CA
                Assert.Equal(3, crls.Count);
                Assert.Equal(0, ocps.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 4)
            {
                //belgian resigned CA
                Assert.Equal(5, crls.Count); //the last one isn't oudated yet (put to 6 when it is expired)
                Assert.Equal(0, ocps.Count);
            }
            else
            {
                Assert.False(true, "The chain should be 4 or 2 long");
            }

        }

        [Fact]
        public void EHealthTsWithCert()
        {
            //if (DateTime.UtcNow > new DateTime(2016, 3, 17, 11, 25, 11, DateTimeKind.Utc)) Assert.Inconclusive("The timestamp should have been renewed");

            TimeStampToken tst = File.ReadAllBytes("files/ehTs.ts").ToTimeStampToken();
            var extraCerts = new X509Certificate2Collection();
            extraCerts.Add(new X509Certificate2(@"files/Certipost E-Trust Secondary Qualified CA for Legal Persons.cer"));

            Timestamp ts = tst.Validate(extraCerts);
            Assert.Equal(new DateTime(2014, 3, 15, 11, 50, 48, 128, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.Equal(new DateTime(2016, 3, 17, 10, 25, 11, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.RevocationStatusUnknown));
        }

        [Fact]
        public void EHealthTsWithoutCert()
        {
            TimeStampToken tst = File.ReadAllBytes("files/ehTs2.ts").ToTimeStampToken();
            var extraCerts = new X509Certificate2Collection();
            extraCerts.Add(new X509Certificate2(@"files/EHEALTH-ECIS-PRD-1_SN_CFB3-96A5-AFCB_01.cer"));
            extraCerts.Add(new X509Certificate2(@"files/EHEALTH-ECIS-PRD-2_SN_2BDB-96DB-5692_01.cer"));
            extraCerts.Add(new X509Certificate2(@"files/EHEALTH-PLATFORM-BCP-2_SN_B65E-8417-F260_01.cer"));
            extraCerts.Add(new X509Certificate2(@"files/EHEALTH-PLATFORM-PRD-2_SN_D7E6-28F4-8360_01.cer"));
            extraCerts.Add(new X509Certificate2(@"files/EHEALTH-PLATFORM-PRD-3_SN_9C8B-842C-C94A_01.cer"));

            Timestamp ts = tst.Validate(extraCerts);
            Assert.Equal(new DateTime(2021, 7, 01, 14, 52, 9, 924, DateTimeKind.Utc).ToString("o"), ts.Time.ToString("o"));
            Assert.Equal(new DateTime(2022, 1, 13, 9, 30, 58, DateTimeKind.Utc).ToString("o"), ts.RenewalTime.ToString("o"));
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }
    }
}
