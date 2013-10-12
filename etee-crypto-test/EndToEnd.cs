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

using Siemens.EHealth.Etee.Crypto.Encrypt;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Resources;
using Siemens.EHealth.Etee.Crypto;
using ETEE = Siemens.EHealth.Etee.Crypto;
using System.IO;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using Siemens.EHealth.Etee.Crypto.Utils;
using NUnit.Framework;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for Seal
    /// </summary>
    [TestFixture]
    public class EndToEnd
    {
        public EndToEnd()
        {

        }

        static X509Certificate2 alice;

        static X509Certificate2 aliceEnc;

        static X509Certificate2 bob;

        static X509Certificate2 bobEnc;

        [TestFixtureSetUp]
        public static void InitializeClass()
        {
            //Alice, used as sender
            alice = new X509Certificate2("../../imports/users/alice_auth.p12", "test", X509KeyStorageFlags.Exportable);
            aliceEnc = new X509Certificate2("../../imports/users/alice_enc.p12", "test", X509KeyStorageFlags.Exportable);
            //Bob, used as receiver
            bob = new X509Certificate2("../../imports/users/bob_auth.p12", "test", X509KeyStorageFlags.Exportable);
            bobEnc = new X509Certificate2("../../imports/users/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);
        }

        [Test]
        public void Addressed()
        {
            Addressed(DataSealerFactory.Create(alice), DataUnsealerFactory.Create(bobEnc, bob));
        }

        private void Addressed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice for Bob";

            //Get ETK
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            //receiver.Verify();

            Stream output = sealer.Seal(receiver, new MemoryStream(Encoding.UTF8.GetBytes(str)));

            UnsealResult result = unsealer.Unseal(output);

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.AreEqual(bobEnc.Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void MultiAddressed()
        {
            String str = "This is a secret message from Alice for Bob and Herself";

            //Get ETK
            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            //receiver1.Verify();
            EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully("../../alice/alices_public_key.etk"));
            //receiver2.Verify();

            IDataSealer sealer = DataSealerFactory.Create(alice);
            List<EncryptionToken> receivers = new List<EncryptionToken>();
            receivers.Add(receiver1);
            receivers.Add(receiver2);
            Stream output = sealer.Seal(new ReadOnlyCollection<EncryptionToken>(receivers), new MemoryStream(Encoding.UTF8.GetBytes(str)));

            IDataUnsealer unsealer = DataUnsealerFactory.Create(bobEnc, bob);
            UnsealResult result = unsealer.Unseal(output);

            output.Position = 0;

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.AreEqual(bobEnc.Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());


            unsealer = DataUnsealerFactory.Create(aliceEnc, alice);
            result = unsealer.Unseal(output);

            output.Close();

            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.AreEqual(aliceEnc.Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void NonAddressed()
        {
            NonAddressed(DataSealerFactory.Create(alice), DataUnsealerFactory.Create());
        }

        private void NonAddressed(IDataSealer sealer, IAnonymousDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice";

            SecretKey key = new SecretKey("btSefztkXjZmlZyHQIumLA==", "aaUnRynIwd3GFQmhXfW+VQ==");
            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), key);

            UnsealResult result = unsealer.Unseal(output, key);

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.IsNull(result.SecurityInformation.Encryption.Subject);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void Mixed()
        {
            Mixed(DataSealerFactory.Create(alice), DataUnsealerFactory.Create(bobEnc, bob), DataUnsealerFactory.Create());
        }

        private void Mixed(IDataSealer sealer, IDataUnsealer unsealer, IAnonymousDataUnsealer unsealerAnon)
        {
            String str = "This is a secret message from Alice to everybody";

            SecretKey key = new SecretKey("btSefztkXjZmlZyHQIumLA==", "aaUnRynIwd3GFQmhXfW+VQ==");

            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            //receiver1.Verify();

            List<EncryptionToken> receivers = new List<EncryptionToken>();
            receivers.Add(receiver1);

            byte[] output = sealer.Seal(new ReadOnlyCollection<EncryptionToken>(receivers), Encoding.UTF8.GetBytes(str), key);

            UnsealResult result = unsealerAnon.Unseal(output, key);

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(MemoryStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.IsNull(result.SecurityInformation.Encryption.Subject);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());


            result = unsealer.Unseal(output);

            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(MemoryStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(alice.Thumbprint, result.Sender.Thumbprint);
            Assert.AreEqual(bobEnc.Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [Test]
        public void Eid()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection nonRep = my.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);
                X509Certificate2UI.SelectFromCollection(nonRep, "Select your eID", "Select the eID you want to used to sign the msg", X509SelectionFlag.SingleSelection);

            }
            finally
            {
                my.Close();
            }
        }

        [Test]
        public void ReuseOfSealerAndUnsealer()
        {
            IDataSealer sealer = DataSealerFactory.Create(alice);
            IDataUnsealer unsealer = DataUnsealerFactory.Create(bobEnc, bob);
            IDataUnsealer unsealerAlice = DataUnsealerFactory.Create(aliceEnc, alice);

            Addressed(sealer, unsealer);
            NonAddressed(sealer, unsealer);
            Mixed(sealer, unsealer, unsealerAlice);
            Mixed(sealer, unsealer, unsealerAlice);
            NonAddressed(sealer, unsealer);
            Addressed(sealer, unsealer);
        }

        [Test]
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
                //receiver.Verify();

                //Seal
                IDataSealer sealer = DataSealerFactory.Create(alice);
                Stream output = sealer.Seal(receiver, hudgeFile);
                hudgeFile.Position = 0;

                UnsealResult result;
                using (output)
                {
                    //Unseal again
                    IDataUnsealer unsealer = DataUnsealerFactory.Create(bobEnc, bob);
                    result = unsealer.Unseal(output);
                }

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
