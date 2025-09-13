using System.Runtime.Remoting.Messaging;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Egelke.Eid.Client;

namespace etee_crypto_xtests
{
    public class SenderTest
    {
        public static IEnumerable<object[]> GetCerts()
        {
            List<object[]> certs = new List<object[]>();
            using (var readers = new Readers(ReaderScope.User))
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                certs = readers.ListCards()
                    .OfType<EidCard>()
                    .Select(c =>
                    {
                        c.Open();
                        String thumbprint = c.AuthCert.Thumbprint;
                        c.Close();
                        return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)[0];
                    })
                    .Select(c => new object[] { new MyX509Certificate2(c) })
                    .ToList();
            }
            var certp12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            certs.Add(new object[] { new MyX509Certificate2(certp12["authentication"]) });

            return certs;
        }

        [Fact]
        public void Test1()
        {

        }
    }
}