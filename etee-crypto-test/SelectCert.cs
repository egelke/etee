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
using Siemens.EHealth.Etee.Crypto.Status;
using System.Configuration;
using System.Collections.Specialized;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Siemens.eHealth.ETEE.Crypto.Test
{

    [TestFixture]
    public class SelectCert
    {
        static X509Certificate2 cert;

        static X509Certificate2 aliceEnc;

        static X509Certificate2 bobEnc;

        static X509Certificate2Collection both;

        [TestFixtureSetUp]
        public static void InitializeClass()
        {
            //ask the sender
            cert = AskCertificate();

            //Bob (and Alice) used as receiver
            bobEnc = new X509Certificate2("../../imports/users/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);
            aliceEnc = new X509Certificate2("../../imports/users/alice_enc.p12", "test", X509KeyStorageFlags.Exportable);
            both = new X509Certificate2Collection(new X509Certificate2[] { bobEnc, aliceEnc });
        }

        [Test]
        public void Online()
        {
            
            String str = "This is a secret message from Alice for Bob";

            Stream output = Seal(str, cert);

            UnsealAndVerify(str, cert, output, EHealth.Etee.Crypto.Status.TrustStatus.Full);
        }

        [Test]
        public void Offline()
        {
            Settings.Default.Offline = true;
            String str = "This is a secret message from Alice for Bob";

            try
            {
                Stream output = Seal(str, cert);

                UnsealAndVerify(str, cert, output, EHealth.Etee.Crypto.Status.TrustStatus.Unsure);
            }
            finally
            {
                Settings.Default.Offline = false;
            }
        }

        [Test]
        public void OfflineVsOnline()
        {
            String str = "This is a secret message from Alice for Bob";

            Settings.Default.Offline = true;
            Stream output;
            try
            {
                output = Seal(str, cert);

            }
            finally
            {
                Settings.Default.Offline = false;
            }

            UnsealAndVerify(str, cert, output, EHealth.Etee.Crypto.Status.TrustStatus.Full);
        }

        private static void UnsealAndVerify(String str, X509Certificate2 cert, Stream output, ETEE::Status.TrustStatus trustStatus)
        {
            IDataUnsealer unsealer = DataUnsealerFactory.Create(true, both);
            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            output.Close();

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);

            //Assert.IsInstanceOfType(result.UnsealedData, typeof(WindowsTempFileStream));
            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(trustStatus, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(cert.Thumbprint, result.Sender.Thumbprint);
            Assert.AreEqual(bobEnc.Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(str, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        private static Stream Seal(String str, X509Certificate2 cert)
        {
            IDataSealer sealer = DataSealerFactory.Create(cert);

            //Get ETK
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            //receiver.Verify();

            Stream output = sealer.Seal(receiver, new MemoryStream(Encoding.UTF8.GetBytes(str)));
            return output;
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

    }
}
