/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Etee.Crypto.Receiver;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto;
using NUnit.Framework;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Client.Pki;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestFixture]
    public class JavaV16IntegrationTest
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private IDataSealer aliceSealer;

        private IDataUnsealer bobUnsealer;

        private IDataUnsealer anonUnsealer;

        [TestFixtureSetUp]
        public void MyClassInitialize()
        {

            var alice = new EHealthP12("../../alice/old_alices_private_key_store.p12", "test");
            var bob = new EHealthP12("../../bob/old_bobs_private_key_store.p12", "test");


            aliceSealer = EhDataSealerFactory.Create(Level.B_Level, alice);
            bobUnsealer = DataUnsealerFactory.Create(null, bob);
            anonUnsealer = DataUnsealerFactory.Create(null);
        }

        private String RunJava(String program)
        {
            String result; 

            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "java.exe";
            p.StartInfo.Arguments = @"-cp ..\..\javabin\v1.6\SIGNED-etee-crypto-1.6.1-tests.jar;..\..\javabin\v1.6\SIGNED-etee-crypto-1.6.1.jar;..\..\javabin\lib\bcmail-jdk16-145.jar;..\..\javabin\lib\bcprov-jdk16-145.jar;..\..\javabin\lib\junit-4.8.2.jar;..\..\javabin\lib\log4j-1.2.16.jar " + program;
            p.Start();

            result = p.StandardOutput.ReadToEnd();
            System.Console.WriteLine(result);
            p.WaitForExit();
            String error = p.StandardError.ReadToEnd();
            if (!String.IsNullOrWhiteSpace(error))
            {
                throw new Exception(error);
            }
            return result;
        }

        [Test]
        public void Java2NetAddressed()
        {
            RunJava("be.smals.ehealth.etee.crypto.examples.Seal");

            UnsealResult result;
            FileStream file = new FileStream("message_from_alice_for_bob.msg", FileMode.Open);
            using (file)
            {
                result = bobUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(2, result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Count);
            //v1.6 does not add the chain of certificates, only the leaf
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            //Old bob and alice don't have the right key usage
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.AuthenticationCertificate.Subject.Contains("NIHII=00000000101"));

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a secret message from Alice for Bob written at "));
        }

       
        [Test]
        public void Net2JavaAddressed()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            Stream msg = aliceSealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/old_bobs_public_key.etk")));

            FileStream msgFile = new FileStream("message_from_alice_for_bob.msg", FileMode.OpenOrCreate);
            msg.CopyTo(msgFile);
           
            String output = RunJava("be.smals.ehealth.etee.crypto.examples.Unseal");

            Assert.IsTrue(output.Contains("NIHII=00000000101"));
            Assert.IsTrue(output.Contains(text));
        }

        
        [Test]
        public void Java2NetUnaddressed()
        {
            RunJava("be.smals.ehealth.etee.crypto.examples.SealForUnknown");

            UnsealResult result;
            SecretKey kek = new SecretKey(Convert.FromBase64String("btSefztkXjZmlZyHQIumLA=="), Convert.FromBase64String("aaUnRynIwd3GFQmhXfW+VQ=="));
            FileStream fs = new FileStream("message_from_alice_for_unknown.msg", FileMode.Open);
            using(fs)
            {
                result = anonUnsealer.Unseal(fs, kek);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(2, result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Count);
            //v1.6 does not add the chain of certificates, only the leaf
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            //Old bob and alice don't have the right key usage
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.AuthenticationCertificate.Subject.Contains("NIHII=00000000101"));

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a secret message from Alice for an unknown addressee written at "));
        }


        [Test]
        public void Net2JavaUnaddressed()
        {
            String text = "This is a secret message from Alice for an unknown addressee written at " + DateTime.Now.ToString();

            SecretKey kek = new SecretKey(Convert.FromBase64String("btSefztkXjZmlZyHQIumLA=="), Convert.FromBase64String("aaUnRynIwd3GFQmhXfW+VQ=="));
            
            Stream msg = aliceSealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), kek);

            FileStream msgFile = new FileStream("message_from_alice_for_unknown.msg", FileMode.OpenOrCreate);
            msg.CopyTo(msgFile);

            String output = RunJava("be.smals.ehealth.etee.crypto.examples.UnsealByUnknown");

            Assert.IsTrue(output.Contains("NIHII=00000000101"));
            Assert.IsTrue(output.Contains(text));
        }

    }
}
