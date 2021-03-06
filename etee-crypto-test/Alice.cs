﻿/*
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
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Client.Pki;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for Seal
    /// </summary>
    [TestClass]
    public class Alice
    {
        private static string _basePath = Path.GetDirectoryName(typeof(Alice).Assembly.Location);
        private static string GetAbsoluteTestFilePath(string relativePath) => Path.Combine(_basePath, relativePath);

        static EHealthP12 alice;

        static EHealthP12 bob;

        static X509Certificate2Collection both;
        static X509Certificate2Collection aliceOnly;
        static X509Certificate2Collection bobOnly;

        [ClassInitialize]
        public static void InitializeClass(TestContext ctx)
        {
            //Load eHealth certificates
            alice = new EHealthP12(GetAbsoluteTestFilePath("alice/alices_private_key_store.p12"), "test");
            bob = new EHealthP12(GetAbsoluteTestFilePath("bob/bobs_private_key_store.p12"), "test");

            AsymmetricAlgorithm key = RSA.Create();
            String keyID = "myid";
        }

        [TestMethod]
        public void Addressed()
        {
            Addressed(EhDataSealerFactory.Create(Level.B_Level, alice), DataUnsealerFactory.Create(null, alice, bob));
        }

        private void Addressed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice for Bob";

            //Get ETK
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));

            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), receiver);

            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [TestMethod]
        public void MultiAddressed()
        {
            String str = "This is a secret message from Alice for Bob and Herself";

            //Get ETK
            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));
            EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("alice/alices_public_key.etk")));

            IDataSealer sealer = EhDataSealerFactory.Create(Level.B_Level, alice);
            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(str)), receiver1, receiver2);

            IDataUnsealer unsealer = DataUnsealerFactory.Create(null, alice, bob);
            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());


            unsealer = DataUnsealerFactory.Create(null, alice);
            result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;


            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(alice["1204544406096826217265"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());

            unsealer = DataUnsealerFactory.Create(null, bob);
            result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Position = 0;

            output.Close();

            stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [TestMethod]
        public void NonAddressed()
        {
            NonAddressed(EhDataSealerFactory.Create(Level.B_Level, alice), DataUnsealerFactory.Create(null));
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
            Assert.IsTrue(result.IsNonRepudiatable);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(alice["Authentication"].Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.IsNull(result.SecurityInformation.Encryption.Subject);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        [TestMethod]
        public void Mixed()
        {
            Mixed(EhDataSealerFactory.Create(Level.B_Level, alice), DataUnsealerFactory.Create(null, alice, bob));
        }

        private void Mixed(IDataSealer sealer, IDataUnsealer unsealer)
        {
            String str = "This is a secret message from Alice to everybody";

            SecretKey key = new SecretKey("btSefztkXjZmlZyHQIumLA==", "aaUnRynIwd3GFQmhXfW+VQ==");

            EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));

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

        [TestMethod]
        public void ReuseOfSealerAndUnsealer()
        {
            IDataSealer sealer = EhDataSealerFactory.Create(Level.B_Level, alice);
            IDataUnsealer unsealer = DataUnsealerFactory.Create(null, bob);
            IDataUnsealer unsealerAlice = DataUnsealerFactory.Create(null, alice);

            Addressed(sealer, unsealer);
            NonAddressed(sealer, unsealer);
            Mixed(sealer, unsealer);
            Mixed(sealer, unsealer);
            NonAddressed(sealer, unsealer);
            Addressed(sealer, unsealer);
        }

        [TestMethod]
        public void Size31KFile()
        {
            Random rand = new Random();
            byte[] buffer = new byte[1024]; //1k blocks
            String file = Path.GetTempFileName();
            FileStream hudgeFile = new FileStream(file, FileMode.Open);
            try
            {
                //Write random stuff into it, exactly 32K
                for (int i = 0; i < 31; i++)
                {
                    rand.NextBytes(buffer);
                    hudgeFile.Write(buffer, 0, buffer.Length);
                }
                rand.NextBytes(buffer);
                hudgeFile.Write(buffer, 0, 512);
                //Rest
                hudgeFile.Position = 0;

                //Get ETK
                EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));

                //Seal
                IDataSealer sealer = EhDataSealerFactory.Create(Level.B_Level, alice);
                Stream output = sealer.Seal(hudgeFile, receiver);
                hudgeFile.Position = 0;

                UnsealResult result;
                using (output)
                {
                    //Unseal again
                    IDataUnsealer unsealer = DataUnsealerFactory.Create(null, alice, bob);
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
            finally
            {
                hudgeFile.Close();
                File.Delete(file);
            }
        }

        [TestMethod, Ignore]
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
                EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));

                //Seal
                IDataSealer sealer = EhDataSealerFactory.Create(Level.B_Level, alice);
                Stream output = sealer.Seal(hudgeFile, receiver);
                hudgeFile.Position = 0;

                UnsealResult result;
                using (output)
                {
                    //Unseal again
                    IDataUnsealer unsealer = DataUnsealerFactory.Create(null, alice, bob);
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
