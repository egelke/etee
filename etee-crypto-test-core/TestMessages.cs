using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class TestMessages
    {

        static EHealthP12 alice;
        static EHealthP12 bob;

        private IDataUnsealer bUnsealer = DataUnsealerFactory.Create(Level.B_Level,
            new EHealthP12("alice/alices_private_key_store.p12", "test"));


        //[TestMethod]
        public void WebAuth()
        {
            UnsealResult result;
            FileStream file = new FileStream("msg/web-auth.cms", FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file, new WebKey(alice["authentication"].PublicKey.Key));
            }
            System.Console.WriteLine(result.SecurityInformation);


            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        
    }
}
