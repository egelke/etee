
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;


using System.Threading.Tasks;
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{

    public class CertTest : IClassFixture<BERootCAFicture>, IClassFixture<ZTRootCAFicture>
    {
        public CertTest(BERootCAFicture becaFicture, ZTRootCAFicture ztcaFicture)
        {
            bool install = false;

            Dictionary<String, bool> beca = becaFicture.Verify();
            if (!install)
            {
                if (!beca["ca4"]) throw new InvalidOperationException("Tests will fail due to missing root CA4, switch the install flag in the test code to install");
                if (!beca["CA2"]) throw new InvalidOperationException("Tests will fail due to missing root CA2, switch the install flag in the test code to install");
            } 
            else
            {
                becaFicture.Install("CA2", "CA4");
            }

            Dictionary<String, bool> ztca = ztcaFicture.Verify();
            if(!install)
            {
                if (!ztca["001"]) throw new InvalidOperationException("Tests will fail due to missing root 001, switch the install flag in the test code to install");
            }
            else
            {
                ztcaFicture.Install("001");
            }
        }

        [Fact]
        public void TestOldEid_ForgetExtra()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();

            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore);

            Assert.Equal(1, rsp.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.PartialChain));
            Assert.Equal(1, rsp.ChainElements.Count);
        }

        [Fact]
        public void TestOldEid_NoRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection
            {
                new X509Certificate2(@"files/Citizen201204.crt")
            };

            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore);

            Assert.Equal(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(3, rsp.ChainElements.Count);
            Assert.Equal("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.Equal("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.Equal("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
        }

        [Fact]
        public void TestOldEid_FailToGetRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection
            {
                new X509Certificate2(@"files/Citizen201204.crt")
            };

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore, crls, ocsps);

            Assert.Equal(1, rsp.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.RevocationStatusUnknown));
            Assert.Equal(3, rsp.ChainElements.Count);
            Assert.Equal("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.Equal("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.Equal("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
        }

        [Fact]
        public void TestOldEid_WithHistoricalRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection
            {
                new X509Certificate2(@"files/Citizen201204.crt")
            };

            IList<CertificateList> crls = new List<CertificateList>
            {
                CertificateList.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/Citizen201204.crl")))
            };
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>
            {
                BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145.ocsp")))
            };
            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore, crls, ocsps);

            Assert.Equal(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(3, rsp.ChainElements.Count);
            Assert.Equal("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.Equal("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.Equal("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.Equal(1, crls.Count);
            Assert.Equal(1, ocsps.Count);
        }

        [Fact]
        public void TestNewEid_GetRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145-2027.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection
            {
                new X509Certificate2(@"files/Citizen201709.crt")
            };

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = target.BuildChain(DateTime.UtcNow, extraStore, crls, ocsps);

            Assert.Equal(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(3, rsp.ChainElements.Count);
            Assert.Equal("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.Equal("SERIALNUMBER=201709, CN=Citizen CA, O=http://repository.eid.belgium.be/, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.Equal("CN=Belgium Root CA4, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.Equal(1, crls.Count);
            Assert.Equal(1, ocsps.Count);
        }

        [Fact]
        public async Task TestNewEid_GetRevocationAsync()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145-2027.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection
            {
                new X509Certificate2(@"files/Citizen201709.crt")
            };

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = await target.BuildChainAsync(DateTime.UtcNow, extraStore, crls, ocsps);

            Assert.Equal(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(3, rsp.ChainElements.Count);
            Assert.Equal("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.Equal("SERIALNUMBER=201709, CN=Citizen CA, O=http://repository.eid.belgium.be/, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.Equal("CN=Belgium Root CA4, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.Equal(1, crls.Count);
            Assert.Equal(1, ocsps.Count);
        }
    }
}
