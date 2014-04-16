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
    public class JavaV20IntegrationTest
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee.Test");

        EHealthP12 bob;

        [TestFixtureSetUp]
        public void MyClassInitialize()
        {
            bob = new EHealthP12("../../bob/bobs_private_key_store.p12", "test");
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
            p.StartInfo.Arguments = @"-cp ..\..\javabin\v2.0\etee-crypto-test.jar;..\..\javabin\v2.0\etee-crypto-lib-2.0.0_beta-0.jar;..\..\javabin\lib\bcmail-jdk15on-146.jar;..\..\javabin\lib\bcprov-jdk15on-146.jar;..\..\javabin\lib\bctsp-jdk15on-146.jar;..\..\javabin\lib\junit-4.8.2.jar;..\..\javabin\lib\log4j-1.2.16.jar;..\..\javabin\lib\commons-logging-1.1.3.jar;..\..\javabin\lib\commons-eid-client-0.4.0.jar;..\..\javabin\lib\commons-eid-dialogs-0.4.0.jar;..\..\javabin\lib\commons-eid-jca-0.4.0.jar " + program;
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
        public void Java2NetAddressedBLevel()
        {
            RunJava("etee.crypto.test.Seal NONE");

            UnsealResult result;
            FileStream file = new FileStream("message_to_bob.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(null, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);
            
            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTLevel()
        {
            RunJava("etee.crypto.test.Seal NONE");

            File.Copy("message_to_bob.msg", "message_to_store.msg", true);

            String output = RunJava("etee.crypto.test.Verify OPTIONAL");

            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Convert.FromBase64String(output.Trim()));

            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2");

            var tsProvider = new EHealthTimestampProvider(tsa);
            byte[] tst = tsProvider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            File.Copy("message_to_bob.msg", "message_to_store.msg", true);

            RunJava("etee.crypto.test.Stamp " + Convert.ToBase64String(tst));

            UnsealResult result;
            FileStream file = new FileStream("message_to_bob.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(Level.LT_Level, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTLevelTma()
        {
            RunJava("etee.crypto.test.Seal MANDATORY");

            UnsealResult result;
            FileStream file = new FileStream("message_to_bob.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.CreateFromTimemarkAuthority(Level.LT_Level, new CurrentTimemarkProvider(), bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTALevel()
        {
            RunJava("etee.crypto.test.Seal NONE");

            File.Copy("message_to_bob.msg", "message_to_store.msg", true);

            String output = RunJava("etee.crypto.test.Verify OPTIONAL");

            SHA256 sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Convert.FromBase64String(output.Trim()));

            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2");

            var tsProvider = new EHealthTimestampProvider(tsa);
            byte[] tst = tsProvider.GetTimestampFromDocumentHash(hash, "http://www.w3.org/2001/04/xmlenc#sha256");

            File.Copy("message_to_bob.msg", "message_to_store.msg", true);

            RunJava("etee.crypto.test.Stamp " + Convert.ToBase64String(tst));

            UnsealResult result;
            FileStream file = new FileStream("message_to_bob.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(Level.LTA_Level, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTALevelCached()
        {
            UnsealResult result;
            FileStream file = new FileStream("../../msg/LTA_eHTSA.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.Create(Level.LTA_Level, bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTALevelTma()
        {
            RunJava("etee.crypto.test.Seal MANDATORY");

            UnsealResult result;
            FileStream file = new FileStream("message_to_bob.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.CreateFromTimemarkAuthority(Level.LTA_Level, new CurrentTimemarkProvider(), bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Java2NetAddressedLTALevelTmaCached()
        {
            UnsealResult result;
            FileStream file = new FileStream("../../msg/LTA_Tma.msg", FileMode.Open);
            using (file)
            {
                IDataUnsealer unsealer = DataUnsealerFactory.CreateFromTimemarkAuthority(Level.LTA_Level, new FixedTimemarkProvider(new DateTime(2014, 4, 8, 20, 36, 30, DateTimeKind.Local)), bob);
                result = unsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(Egelke.EHealth.Etee.Crypto.Status.TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);

            Assert.AreEqual("SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE", result.AuthenticationCertificate.Subject);

            byte[] bytes = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(bytes, 0, bytes.Length);
            String msg = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(msg.StartsWith("This is a message to bob"));
        }

        [Test]
        public void Net2JavaAddressedBLevel()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            IDataSealer sealer = EidDataSealerFactory.Create(Level.B_Level, new TimeSpan(0, 5, 0));
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")));

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Unseal NONE"); //should be OK

            Assert.IsTrue(output.Contains(text));

            try
            {
                output = RunJava("etee.crypto.test.Unseal MANDATORY"); //should fail, with exception
                Assert.Fail();
            }
            catch (InvalidOperationException)
            {

            }

        }

        [Test]
        public void Net2JavaAddressedLTLevel()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2");

            IDataSealer sealer = EidDataSealerFactory.Create(Level.LT_Level, new EHealthTimestampProvider(tsa), new TimeSpan(0, 5, 0));
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")));

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains(text));
        }

        [Test]
        public void Net2JavaAddressedLTLevelInSteps()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            var tsa = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
            tsa.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2");

            IDataSealer sealer = EidDataSealerFactory.Create(Level.B_Level, new TimeSpan(0, 5, 0));
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")));

            IDataCompleter completer = DataCompleterFactory.Create(Level.LT_Level, new EHealthTimestampProvider(tsa));
            Stream msg2 = completer.Complete(msg);

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg2.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains(text));
        }

        [Test]
        public void Net2JavaAddressedLTLevelFedict()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            IDataSealer sealer = EidDataSealerFactory.Create(Level.LT_Level, new Rfc3161TimestampProvider(), new TimeSpan(0, 5, 0));
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")));

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains(text));
        }

        [Test]
        public void Net2JavaAddressedLTLevelTma()
        {
            String text = "This is a secret message from Alice for Bob written at " + DateTime.Now.ToString();

            IDataSealer sealer = EidDataSealerFactory.CreateForTimemarkAuthority(Level.LT_Level, new TimeSpan(0, 5, 0));
            Stream msg = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(text)), new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk")));

            FileStream msgFile = new FileStream("message_to_bob.msg", FileMode.OpenOrCreate);
            using (msgFile)
            {
                msg.CopyTo(msgFile);
            }

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains(text));
        }

        [Test]
        public void OldNet2JavaAddressedLTLevel()
        {
            File.Copy("../../msg/LT_eHTSA.msg", "message_to_bob.msg", true);

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains("This is a secret message from Alice for Bob written at 31/03/2014 16:03:03"));
        }

        [Test]
        public void OldNet2JavaAddressedLTLevelFedict()
        {
            File.Copy("../../msg/LT_FedictTSA.msg", "message_to_bob.msg", true);

            String output = RunJava("etee.crypto.test.Unseal MANDATORY");

            Assert.IsTrue(output.Contains("This is a secret message from Alice for Bob written at 31/03/2014 16:40:25"));
        }


    }
}
