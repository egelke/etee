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

using Egelke.EHealth.Etee.Crypto.Sender;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Resources;
using Egelke.EHealth.Etee.Crypto;
using ETEE = Egelke.EHealth.Etee.Crypto;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Receiver;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using Egelke.EHealth.Etee.Crypto.Utils;
using NUnit.Framework;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Client.Tool;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for Seal
    /// </summary>
    [TestFixture]
    public class Alice
    {

        static EHealthP12 alice;

        static EHealthP12 bob;

        static X509Certificate2Collection both;
        static X509Certificate2Collection aliceOnly;
        static X509Certificate2Collection bobOnly;

        [TestFixtureSetUp]
        public static void InitializeClass()
        {
            //Load eHealth certificates
            alice = new EHealthP12("../../alice/alices_private_key_store.p12", "test");
            bob = new EHealthP12("../../bob/bobs_private_key_store.p12", "test");

            //Add the Alice certs to the extra store
            X509Certificate2[] extraCerts = new X509Certificate2[alice.Values.Count];
            alice.Values.CopyTo(extraCerts, 0);
            Settings.Default.ExtraStore = new X509Certificate2Collection(extraCerts);

            both = new X509Certificate2Collection(new X509Certificate2[] { alice["1204544406096826217265"], bob["825373489"] });
            aliceOnly = new X509Certificate2Collection(new X509Certificate2[] { alice["1204544406096826217265"] });
            bobOnly = new X509Certificate2Collection(new X509Certificate2[] { bob["825373489"] });
        }

        [Test]
        public void Addressed()
        {
            Addressed(DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level), DataUnsealerFactory.Create(both, null));
        }

        private void Addressed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice for Bob";

            //Get ETK
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            //receiver.Verify();

            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), receiver);

            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void MultiAddressed()
        {
            String str = "This is a secret message from Alice for Bob and Herself";

            //Get ETK
            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully("../../alice/alices_public_key.etk"));

            IDataSealer sealer = DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level);
            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), receiver1, receiver2);

            IDataUnsealer unsealer = DataUnsealerFactory.Create(both, null);
            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());


            unsealer = DataUnsealerFactory.Create(aliceOnly, null);
            result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;


            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(alice["1204544406096826217265"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());

            unsealer = DataUnsealerFactory.Create(bobOnly, null);
            result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;

            output.Close();

            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void NonAddressed()
        {
            NonAddressed(DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level), DataUnsealerFactory.Create(new X509Certificate2Collection(), null));
        }

        private void NonAddressed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice";

            SecretKey key = new SecretKey("btSefztkXjZmlZyHQIumLA==", "aaUnRynIwd3GFQmhXfW+VQ==");
            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), key);

            UnsealResult result = unsealer.Unseal(output, key);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.IsNull(result.SecurityInformation.Encryption.Subject);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void Mixed()
        {
            Mixed(DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level), DataUnsealerFactory.Create(both, null));
        }

        private void Mixed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice to everybody";

            SecretKey key = new SecretKey("btSefztkXjZmlZyHQIumLA==", "aaUnRynIwd3GFQmhXfW+VQ==");

            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));

            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), key, receiver1);

            UnsealResult result = unsealer.Unseal(output, key);
            Console.WriteLine(result.SecurityInformation.ToString());

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.IsNull(result.SecurityInformation.Encryption.Subject);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());

            output.Position = 0;
            result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void ReuseOfSealerAndUnsealer()
        {
            IDataSealer sealer = DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level);
            IDataUnsealer unsealer = DataUnsealerFactory.Create(bobOnly, null);
            IDataUnsealer unsealerAlice = DataUnsealerFactory.Create(aliceOnly, null);

            Addressed(sealer, unsealer);
            NonAddressed(sealer, unsealer);
            Mixed(sealer, unsealer);
            Mixed(sealer, unsealer);
            NonAddressed(sealer, unsealer);
            Addressed(sealer, unsealer);
        }

        [Test, Explicit, Category("Long")]
        public void HudgeFile()
        {
            Random rand = new Random();
            byte[] buffer = new byte[10240]; //10k blocks
            String file = Path.GetTempFileName();
            FileStream hudgeFile = new FileStream(file, FileMode.Open);
            try
            {
                //Write random stuff into it, for 500 MB
                for (int i = 0; i < 51200; i++)
                {
                    rand.NextBytes(buffer);
                    hudgeFile.Write(buffer, 0, buffer.Length);
                }
                //Rest
                hudgeFile.Position = 0;

                //Get ETK
                EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));

                //Seal
                IDataSealer sealer = DataSealerFactory.Create(alice["Authentication"], null, Level.B_Level);
                Stream output = sealer.Seal(hudgeFile, receiver);
                hudgeFile.Position = 0;

                UnsealResult result;
                using (output)
                {
                    //Unseal again
                    IDataUnsealer unsealer = DataUnsealerFactory.Create(both, null);
                    result = unsealer.Unseal(output);
                }
                Console.WriteLine(result.SecurityInformation.ToString());

                //check the lenth and the first bytes
                Assert.AreEqual(hudgeFile.Length, result.UnsealedData.Length);
                Assert.AreEqual(hudgeFile.ReadByte(), result.UnsealedData.ReadByte());
                Assert.AreEqual(hudgeFile.ReadByte(), result.UnsealedData.ReadByte());
                Assert.AreEqual(hudgeFile.ReadByte(), result.UnsealedData.ReadByte());
                Assert.AreEqual(hudgeFile.ReadByte(), result.UnsealedData.ReadByte());
                Assert.AreEqual(hudgeFile.ReadByte(), result.UnsealedData.ReadByte());

                result.UnsealedData.Dispose();
            }
            finally {
                hudgeFile.Close();
                File.Delete(file);
            }
        }

    }
}
