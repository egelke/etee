using Egelke.EHealth.Client.Sso.Sts;
using Egelke.EHealth.Client.Sso.WA;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.DSS;
using NUnit.Framework;
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

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestFixture]
    public class TimestampProviderTests
    {
        public byte[] msg;
        public byte[] hash;

        [SetUp]
        public void Setup()
        {
            msg = new byte[2048];

            var rand = new Random();
            rand.NextBytes(msg);

            SHA256 sha = SHA256.Create();
            hash = sha.ComputeHash(msg);
        }

        [Test]
        public void NewTsViaFedict()
        {
            var provider = new Rfc3161TimestampProvider();

            byte[] tsBytes = provider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            TimeStampToken tst = tsBytes.ToTimeStampToken();

            Assert.IsTrue(tst.IsMatch(new MemoryStream(msg)));

            //Validate
            Timestamp ts;
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            ts = tst.Validate(ref crls, ref ocps);
            Assert.IsTrue(Math.Abs((DateTime.UtcNow - ts.Time).TotalSeconds) < 60);
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            ts = tst.Validate(ref crls, ref ocps, DateTime.UtcNow); //check clock skewness
            Assert.IsTrue(Math.Abs((DateTime.UtcNow - ts.Time).TotalSeconds) < 60);
            Assert.AreEqual(new DateTime(2019, 1, 23, 11, 0, 0), ts.RenewalTime);
            Assert.AreEqual(0, ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            Assert.AreEqual(0, ts.CertificateChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
        }

        [Test]
        public void NewTsViaEHealth()
        {
            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2");

            var provider = new EHealthTimestampProvider(tsa);

            byte[] tsBytes = provider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            TimeStampToken tst = tsBytes.ToTimeStampToken();

            Assert.IsTrue(tst.IsMatch(new MemoryStream(msg)));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            tst.Validate(ref crls, ref ocps);
            tst.Validate(ref crls, ref ocps, null);
        }
    }
}
