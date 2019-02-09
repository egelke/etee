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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
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
using Org.BouncyCastle.Security;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.DSS;
using System.ServiceModel.Description;
using Egelke.EHealth.Client.Sso.WA;
using Egelke.EHealth.Client.Sso.Sts;
using System.ServiceModel;
using System.Security.Cryptography;
using Egelke.EHealth.Etee.Crypto.Store;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestFixture]
    public class JavaV21IntegrationTest
    {
        private static string _basePath = Path.GetDirectoryName(typeof(Alice).Assembly.Location);
        private static string GetAbsoluteTestFilePath(string relativePath) => Path.Combine(_basePath, relativePath);

        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee.Test");

        EHealthP12 bob;
        EHealthP12 alice;
        EHealthP12 mcn;

        [OneTimeSetUp]
        public void MyClassInitialize()
        {
            bob = new EHealthP12(GetAbsoluteTestFilePath("../../bob/bobs_private_key_store.p12"), "test");
            alice = new EHealthP12(GetAbsoluteTestFilePath("../../alice/alices_private_key_store.p12"), "test");
            mcn = new EHealthP12(GetAbsoluteTestFilePath("../../mcn/MYCARENET.p12"), File.ReadAllText(GetAbsoluteTestFilePath("../../mcn/MYCARENET.pwd")));
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
            p.StartInfo.Arguments = @"-cp " + GetAbsoluteTestFilePath(@"..\..\javabin\v2.1\etee-crypto-test.jar") + " " + program;
            p.StartInfo.WorkingDirectory = _basePath;
            p.Start();

            result = p.StandardOutput.ReadToEnd();
            System.Console.WriteLine(result);
            p.WaitForExit();
            String error = p.StandardError.ReadToEnd();
            if (!String.IsNullOrWhiteSpace(error))
            {
                throw new InvalidOperationException(error);
            }
            return result;
        }


        [Test]
        public void Java2NetBasic()
        {
            RunJava("etee.crypto.test.Seal BASIC");

            //check adressed
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("message_to_bob.msg"), FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(null, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(mcn["authentication"].Subject, result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.AreEqual("Hello from Alice to Bob", msg);

            //check unaddressed
            SecretKey sk = new SecretKey("btSefztkXjZmlZyHQIumLA==", "QUFBQUFBQUFBQUFBQUFBQQ==");
            file = new FileStream(GetAbsoluteTestFilePath("message_to_bob.msg"), FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(null);
                result = unsealer.Unseal(file, sk);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(mcn["authentication"].Subject, result.AuthenticationCertificate.Subject);

            bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            msg = Encoding.UTF8.GetString(bytes);
            Assert.AreEqual("Hello from Alice to Bob", msg);
        }

        [Test]
        public void Java2NetEid()
        {
            RunJava("etee.crypto.test.Seal EID");

            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("message_to_bob.msg"), FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(null, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.IsFalse(result.IsNonRepudiatable);
        }

        [Test]
        public void Net2JavaBasic()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            IDataSealer sealer = EhDataSealerFactory.Create(Level.B_Level, alice);
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("../../bob/bobs_public_key.etk"))));

            FileStream msgFile = new FileStream(GetAbsoluteTestFilePath("message_to_bob.msg"), FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Verify BASIC"); 
            Assert.IsTrue(output.Contains(text));
        }

        [Test]
        public void Net2JavaEid()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            IDataSealer sealer = EidDataSealerFactory.Create(Level.B_Level, new TimeSpan(0, 5, 0), false);
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("../../bob/bobs_public_key.etk"))));

            FileStream msgFile = new FileStream(GetAbsoluteTestFilePath("message_to_bob.msg"), FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Verify EID");
            Assert.IsTrue(output.Contains(text));
        }
    }
}
