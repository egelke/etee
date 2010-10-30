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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.IO;
using Siemens.EHealth.Etee.Crypto.Encrypt;
using Siemens.EHealth.Etee.Crypto;

namespace Siemens.EHealth.Etee.ITest
{
    [TestClass]
    public class JavaIntegrationTest
    {

        private static X509Certificate2 bobEnc;

        private static X509Certificate2 bobAuth;

        private static X509Certificate2 aliceAuth;


        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            bobEnc = new X509Certificate2("users/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);
            bobAuth = new X509Certificate2("users/bob_auth.p12", "test", X509KeyStorageFlags.Exportable);
            aliceAuth = new X509Certificate2("users/alice_auth.p12", "test", X509KeyStorageFlags.Exportable);
        }


        private IDataUnsealer unsealer;

        private IDataSealer sealer;



        [TestInitialize()]
        public void MyTestInitialize()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            sealer = DataSealerFactory.Create(aliceAuth);
        }

        private String RunJava(String program)
        {
            String output;

            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "java.exe";
            p.StartInfo.Arguments = @"-cp v1.6\etee-crypto-tests.jar;v1.6\etee-crypto.jar;lib\bcmail-jdk16-145.jar;lib\bcprov-jdk16-145.jar;lib\junit-4.8.2.jar;lib\log4j-1.2.16.jar " + program;
            p.Start();
            
            output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            String error = p.StandardError.ReadToEnd();
            if (!String.IsNullOrWhiteSpace(error))
            {
                throw new Exception(error);
            }
            return output;
        }

        [TestMethod]
        public void Java2NetAddressed()
        {
            RunJava("be.smals.ehealth.etee.crypto.examples.Seal");

            UnsealResult result;
            FileStream file = new FileStream("message_from_alice_for_bob.msg", FileMode.Open);
            using (file)
            {
                result = unsealer.Unseal(file);
            }
            
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.Sender.Subject.Contains("NIHII=00000000101"));

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a secret message from Alice for Bob written at "));
        }

        [TestMethod]
        public void Net2JavaAddressed()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            byte[] msg = sealer.Seal(new Crypto.EncryptionToken(Utils.ReadFully("bobs_public_key.etk")), Encoding.UTF8.GetBytes(text));

            FileStream msgFile = new FileStream("message_from_alice_for_bob.msg", FileMode.OpenOrCreate);
            using(msgFile)
            {
                msgFile.Write(msg, 0, msg.Length);
            } 
           
            String output = RunJava("be.smals.ehealth.etee.crypto.examples.Unseal");

            Assert.IsTrue(output.Contains("NIHII=00000000101"));
            Assert.IsTrue(output.Contains(text));
        }

        [TestMethod]
        public void Java2NetUnaddressed()
        {
            RunJava("be.smals.ehealth.etee.crypto.examples.SealForUnknown");

            UnsealResult result;
            SecretKey kek = new SecretKey(Convert.FromBase64String("btSefztkXjZmlZyHQIumLA=="), Convert.FromBase64String("aaUnRynIwd3GFQmhXfW+VQ=="));
            FileStream fs = new FileStream("message_from_alice_for_unknown.msg", FileMode.Open);
            using(fs)
            {
                result = unsealer.Unseal(fs, kek);
            }

            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.Sender.Subject.Contains("NIHII=00000000101"));

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a secret message from Alice for an unknown addressee written at "));
        }

        [TestMethod]
        public void Net2JavaUnaddressed()
        {
            String text = "This is a secret message from Alice for an unknown addressee written at " + DateTime.Now.ToString();

            SecretKey kek = new SecretKey(Convert.FromBase64String("btSefztkXjZmlZyHQIumLA=="), Convert.FromBase64String("aaUnRynIwd3GFQmhXfW+VQ=="));

            byte[] msg = sealer.Seal(Encoding.UTF8.GetBytes(text), kek);

            FileStream msgFile = new FileStream("message_from_alice_for_unknown.msg", FileMode.OpenOrCreate);
            using(msgFile) 
            {
                msgFile.Write(msg, 0, msg.Length);
            }

            String output = RunJava("be.smals.ehealth.etee.crypto.examples.UnsealByUnknown");

            Assert.IsTrue(output.Contains("NIHII=00000000101"));
            Assert.IsTrue(output.Contains(text));
        }
    }
}
