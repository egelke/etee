using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestClass]
    public class CertTest
    {

        public TestContext TestContext { get; set; }

        [TestMethod]
        public void TestOldEid_ForgetExtra()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();

            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore);

            Assert.AreEqual(1, rsp.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.PartialChain));
            Assert.AreEqual(1, rsp.ChainElements.Count);
        }

        [TestMethod]
        public void TestOldEid_NoRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/Citizen201204.crt"));

            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore);

            Assert.AreEqual(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
        }

        [TestMethod]
        public void TestOldEid_FailToGetRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/Citizen201204.crt"));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore, crls, ocsps);

            Assert.AreEqual(1, rsp.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.RevocationStatusUnknown));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
        }

        [TestMethod]
        public void TestOldEid_WithHistoricalRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/Citizen201204.crt"));

            IList<CertificateList> crls = new List<CertificateList>();
            crls.Add(CertificateList.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/Citizen201204.crl"))));
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            ocsps.Add(BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145.ocsp"))));
            Chain rsp = target.BuildChain(new DateTime(2014, 03, 05, 18, 00, 00, DateTimeKind.Utc), extraStore, crls, ocsps);

            Assert.AreEqual(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("SERIALNUMBER=201204, CN=Citizen CA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=Belgium Root CA2, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocsps.Count);
        }

        [TestMethod]
        public void TestNewEid_GetRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145-2027.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/Citizen201709.crt"));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = target.BuildChain(DateTime.UtcNow, extraStore, crls, ocsps);

            Assert.AreEqual(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("SERIALNUMBER=201709, CN=Citizen CA, O=http://repository.eid.belgium.be/, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=Belgium Root CA4, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocsps.Count);
        }

        [TestMethod]
        public async Task TestNewEid_GetRevocationAsync()
        {
            X509Certificate2 target = new X509Certificate2(@"files/eid79021802145-2027.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/Citizen201709.crt"));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = await target.BuildChainAsync(DateTime.UtcNow, extraStore, crls, ocsps);

            Assert.AreEqual(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("SERIALNUMBER=201709, CN=Citizen CA, O=http://repository.eid.belgium.be/, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=Belgium Root CA4, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.AreEqual(1, crls.Count);
            Assert.AreEqual(1, ocsps.Count);
        }

        [TestMethod]
        public void Vitalink_GetRevocation()
        {
            X509Certificate2 target = new X509Certificate2(@"files/vitalink.crt");
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            extraStore.Add(new X509Certificate2(@"files/eHealthIssuing.crt"));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain rsp = target.BuildChain(DateTime.UtcNow, extraStore, crls, ocsps);

            Assert.AreEqual(0, rsp.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(3, rsp.ChainElements.Count);
            Assert.AreEqual("CN=\"EHP=1990001916, VITALINKGATEWAY\", OU=eHealth-platform Belgium, OU=VLAAMS AGENTSCHAP ZORG EN GEZONDHEID, OU=\"EHP=1990001916\", OU=VITALINKGATEWAY, O=Federal Government, C=BE", rsp.ChainElements[0].Certificate.Subject);
            Assert.AreEqual("CN=ZetesConfidens Private Trust PKI - eHealth issuing CA 001, SERIALNUMBER=001, O=ZETES SA, C=BE", rsp.ChainElements[1].Certificate.Subject);
            Assert.AreEqual("CN=ZetesConfidens Private Trust PKI - root CA 001, SERIALNUMBER=001, O=ZETES SA, C=BE", rsp.ChainElements[2].Certificate.Subject);
            Assert.AreEqual(0, crls.Count);
            Assert.AreEqual(2, ocsps.Count);
        }
    }
}
