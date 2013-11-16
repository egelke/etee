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
using Egelke.EHealth.Etee.Crypto.Decrypt;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Encrypt;
using Egelke.EHealth.Etee.Crypto;
using NUnit.Framework;
using Egelke.EHealth.Etee.Crypto.Status;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestFixture]
    public class JavaV20IntegrationTest
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private IDataSealer sealer;

        private IDataUnsealer bobUnsealer;

        private IAnonymousDataUnsealer anonUnsealer;

        [TestFixtureSetUp]
        public void MyClassInitialize()
        {
            X509Certificate2 bobEnc = new X509Certificate2("../../bob/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);

            sealer = DataSealerFactory.Create(AskCertificate());
            bobUnsealer = DataUnsealerFactory.Create(false, new X509Certificate2Collection(new X509Certificate2[] { bobEnc }));
            anonUnsealer = DataUnsealerFactory.Create(false);
        }

        private static X509Certificate2 AskCertificate()
        {
            X509Certificate2 cert;

            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection nonRep = my.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);
                cert = X509Certificate2UI.SelectFromCollection(nonRep, "Select your cert", "Select the cert you want to used to sign the msg", X509SelectionFlag.SingleSelection)[0];
            }
            finally
            {
                my.Close();
            }
            return cert;
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
            p.StartInfo.Arguments = @"-cp ..\..\javabin\v2.0\etee-crypto-test.jar;..\..\javabin\v2.0\etee-crypto-lib-2.0.1.jar;..\..\javabin\lib\bcmail-jdk15on-146.jar;..\..\javabin\lib\bcprov-jdk15on-146.jar;..\..\javabin\lib\junit-4.8.2.jar;..\..\javabin\lib\log4j-1.2.16.jar;..\..\javabin\lib\commons-logging-1.1.3.jar;..\..\javabin\lib\commons-eid-client-0.4.0.jar;..\..\javabin\lib\commons-eid-dialogs-0.4.0.jar;..\..\javabin\lib\commons-eid-jca-0.4.0.jar " + program;
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

        /*
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
            
            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.Sender.Subject.Contains("NIHII=00000000101"));

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a secret message from Alice for Bob written at "));
        }
        */
       
        [Test]
        public void Net2JavaAddressed()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            byte[] msg = sealer.Seal(new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")), Encoding.UTF8.GetBytes(text));

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using(msgFile)
            {
                msgFile.Write(msg, 0, msg.Length);
            }

            String output = RunJava("etee.crypto.test.Unseal L3");

            Assert.IsTrue(output.Contains(text));
        }
        /*
        
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

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.Sender.Subject.Contains("NIHII=00000000101"));

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

            byte[] msg = aliceSealer.Seal(Encoding.UTF8.GetBytes(text), kek);

            FileStream msgFile = new FileStream("message_from_alice_for_unknown.msg", FileMode.OpenOrCreate);
            using(msgFile) 
            {
                msgFile.Write(msg, 0, msg.Length);
            }

            String output = RunJava("be.smals.ehealth.etee.crypto.examples.UnsealByUnknown");

            Assert.IsTrue(output.Contains("NIHII=00000000101"));
            Assert.IsTrue(output.Contains(text));
        }
        */
    }
}
