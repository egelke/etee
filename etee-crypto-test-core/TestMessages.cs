using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class TestMessages
    {

        static EHealthP12 alice = new EHealthP12("alice/alices_private_key_store.p12", "test");
        static EHealthP12 bob = new EHealthP12("bob/bobs_private_key_store.p12", "test");

        private IDataUnsealer bUnsealer = new DataUnsealerFactory(Config.LoggerFactory).Create(Level.B_Level, bob);

        [TestMethod]
        public void WebAuth()
        {
            UnsealResult result;
            FileStream file = new FileStream("msg/web-auth.cms", FileMode.Open);
            using (file)
            {
                X509Certificate2 aliceAuth = alice["authentication"];
                result = bUnsealer.Unseal(file, new WebKey(new byte[] { 0x53, 0x35, 0x39, 0x33, 0x39, 0x31, 0x30, 0x31, 0x37, 0x31, 0x31, 0x32, 0x30, 0x36, 0x32, 0x36, 0x36, 0x31, 0x39, 0x30 }, aliceAuth.PublicKey.Key));
            }
            System.Console.WriteLine(result.SecurityInformation);


            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.Full, result.SecurityInformation.TrustStatus);
            //Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            //Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            //Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        
    }
}
