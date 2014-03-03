using System;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Tsa;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Linq;

namespace Egelke.EHealth.Client.TsaTest
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

        [Test]
        public void AskValid()
        {
            X509Certificate2 cert = AskCertificate(X509KeyUsageFlags.DigitalSignature);

            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocps = new List<BasicOcspResponse>();
            Chain chain = cert.BuildChain(DateTime.UtcNow, null, ref crls, ref ocps, DateTime.UtcNow, true, new TimeSpan(0, 1, 0));

            Assert.IsTrue(crls.Count > 0);
            Assert.IsTrue(ocps.Count > 0);
            Assert.AreEqual(0, chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            foreach(ChainElement element in chain.ChainElements)
            {
                Assert.AreEqual(0, element.ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError));
            }
        }
    }
}
