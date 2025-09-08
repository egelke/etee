using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{
    [Collection("eHealth.acc-p12")]
    public class TimestampProviderTests : IClassFixture<BERootCAFicture>
    {
        public byte[] msg;
        public byte[] hash;

        public TimestampProviderTests(BERootCAFicture becaFicture)
        {
            bool install = false;

            Dictionary<String, bool> beca = becaFicture.Verify();
            if (!install)
            {
                if (!beca["ca6"]) throw new InvalidOperationException("Tests will fail due to missing root CA6, switch the install flag in the test code to install");
            }
            else
            {
                becaFicture.Install("CA6");
            }

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
                Assert.Equal(new DateTime(2028, 12, 09, 10, 56, 1), ts.RenewalTime);
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
    }
}
