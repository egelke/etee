using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.DSS;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Sso;
using Egelke.EHealth.Client.Sso.Sts;
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{
    [Collection("eHealth.acc-p12")]
    public class TimestampProviderTests
    {
        public byte[] msg;
        public byte[] hash;

        public TimestampProviderTests()
        {
            msg = new byte[2048];

            var rand = new Random();
            rand.NextBytes(msg);

            SHA256 sha = SHA256.Create();
            hash = sha.ComputeHash(msg);
        }

        [Fact]
        public void NewTsViaFedict()
        {
            var provider = new Rfc3161TimestampProvider();

            byte[] tsBytes = provider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            TimeStampToken tst = tsBytes.ToTimeStampToken();

            Assert.True(tst.IsMatch(new MemoryStream(msg)));

            //Validate
            Timestamp ts;
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            ts = tst.Validate(crls, ocps);
            Assert.True(Math.Abs((DateTime.UtcNow - ts.Time).TotalSeconds) < 60);
            if (ts.CertificateChain.ChainElements.Count == 2)
            {
                Assert.Equal(new DateTime(2022, 2, 28, 10, 0, 0), ts.RenewalTime);
                Assert.Equal(0, ocps.Count);
                Assert.Equal(1, crls.Count);
            }
            else if (ts.CertificateChain.ChainElements.Count == 3)
            {
                Assert.Equal(new DateTime(2031, 01, 21, 0, 0, 0), ts.RenewalTime);
                Assert.Equal(2, ocps.Count);
                Assert.Equal(0, crls.Count);
            }
            else
            {
                Assert.True(false, "The chain should be 3 (win) or 2 (linux) long");
            }
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));

            ts = tst.Validate(crls, ocps, DateTime.UtcNow); //check clock skewness
            Assert.True(Math.Abs((DateTime.UtcNow - ts.Time).TotalSeconds) < 60);
            //Assert.AreEqual(new DateTime(2022, 2, 28, 10, 0, 0), ts.RenewalTime);
            Assert.Equal(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.Equal(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        [Fact]
        public void NewTsViaEHealth()
        {
            //Read this to enable TLS1.2 on old .Net Framework:
            //https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#configuring-security-via-the-windows-registry

            var certs = new EHealthP12(@"EHealthP12/eHealth.acc-p12", File.ReadAllText(@"EHealthP12/eHealth.acc-p12.pwd"));

            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress(new Uri("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2")));
            tsa.ClientCredentials.ClientCertificate.Certificate = certs["authentication"];

            var provider = new EHealthTimestampProvider(tsa);

            byte[] tsBytes = provider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");
            File.WriteAllBytes(@"files/eHTs2.ts", tsBytes);

            TimeStampToken tst = tsBytes.ToTimeStampToken();

            Assert.True(tst.IsMatch(new MemoryStream(msg)));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            tst.Validate(crls, ocps);
            tst.Validate(crls, ocps, null);
        }
    }
}
