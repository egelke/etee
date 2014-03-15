using Egelke.EHealth.Client.Sso.Sts;
using Egelke.EHealth.Client.Sso.WA;
using Egelke.EHealth.Client.Tsa;
using Egelke.EHealth.Client.Tsa.DSS;
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

namespace Egelke.EHealth.Client.TsaTest
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

            TimeStampToken ts = tsBytes.ToTimeSTampToken();

            Assert.IsTrue(ts.IsMatch(new MemoryStream(msg)));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain chain = ts.Validate(ref crls, ref ocsps);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.NoError));

            File.WriteAllBytes("fedictTs.ts", tsBytes);
            int i = 1;
            foreach (ChainElement element in chain.ChainElements)
            {
                File.WriteAllBytes("fedictTs" + i++ + ".crt", element.Certificate.GetRawCertData());
            }
            i = 1;
            foreach (CertificateList crl in crls)
            {
                File.WriteAllBytes("fedictTs" + i++ + ".crl", crl.GetEncoded());
            }
            i = 1;
            foreach (BasicOcspResponse ocsp in ocsps)
            {
                File.WriteAllBytes("fedictTs" + i++ + ".ocsp", ocsp.GetEncoded());
            }
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

            TimeStampToken ts = tsBytes.ToTimeSTampToken();

            Assert.IsTrue(ts.IsMatch(new MemoryStream(msg)));

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            Chain chain = ts.Validate(ref crls, ref ocsps);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.NoError));

            File.WriteAllBytes("ehTs.ts", tsBytes);
            int i = 1;
            foreach (ChainElement element in chain.ChainElements)
            {
                File.WriteAllBytes("ehTs" + i++ + ".crt", element.Certificate.GetRawCertData());
            }
            i = 1;
            foreach (CertificateList crl in crls)
            {
                File.WriteAllBytes("ehTs" + i++ + ".crl", crl.GetEncoded());
            }
            i = 1;
            foreach (BasicOcspResponse ocsp in ocsps)
            {
                File.WriteAllBytes("ehTs" + i++ + ".ocsp", ocsp.GetEncoded());
            }
        }
    }
}
