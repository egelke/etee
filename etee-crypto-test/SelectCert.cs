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
using System.Configuration;
using System.Collections.Specialized;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Security;
using Egelke.EHealth.Client.Tsa;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Client.Tool;

namespace Egelke.eHealth.ETEE.Crypto.Test
{

    [TestFixture]
    public class SelectCert
    {
        const String clearMessage = "This is a secret message from Alice for Bob";

        static X509Certificate2 authCert;

        static X509Certificate2 signCert;

        static EHealthP12 alice;

        static EHealthP12 bob;

        static X509Certificate2Collection both;

        static EncryptionToken bobEtk;

        static ITimestampProvider tsa;

        Level? level;

        bool useTmaInsteadOfTsa;

        ETEE::Status.TrustStatus trustStatus;

        ValidationStatus validationStatus;

        [TestFixtureSetUp]
        public static void InitializeClass()
        {
            //ask the sender
            authCert = AskCertificate(X509KeyUsageFlags.DigitalSignature);
            if (!DotNetUtilities.FromX509Certificate(authCert).GetKeyUsage()[1])
            {
                signCert = AskCertificate(X509KeyUsageFlags.NonRepudiation);
            }
            else
            {
                signCert = null;
            }

            //Bob as decryption
            bobEtk = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));

            //Bob (and Alice) used for decryption
            alice = new EHealthP12("../../alice/alices_private_key_store.p12", "test");
            bob = new EHealthP12("../../bob/bobs_private_key_store.p12", "test");
            both = new X509Certificate2Collection(new X509Certificate2[] { alice["1204544406096826217265"], bob["825373489"] });

            //create a tsa (fedict in this case)
            tsa = new Rfc3161TimestampProvider();
        }

        [Test]
        public void NullLevel()
        {
            level = null;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnly(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void B_Level()
        {
            level = Level.B_Level;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnly(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void T_Level()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnly(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void T_LevelTma()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnlyFromTma(output);

            output.Position = 0;

            VerifyOnlyAsTma(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void LT_Level()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnly(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void LT_LevelTma()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnlyFromTma(output);

            output.Position = 0;

            VerifyOnlyAsTma(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void LTA_Level()
        {
            level = Level.LTA_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnly(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        [Test]
        public void LTA_LevelTma()
        {
            level = Level.LTA_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            Stream output = Seal();

            VerifyOnlyFromTma(output);

            output.Position = 0;

            VerifyOnlyAsTma(output);

            output.Position = 0;

            UnsealAndVerify(output);

            output.Close();
        }

        private void VerifyOnly(Stream output)
        {
            IDataVerifier verifier;
            if (!level.HasValue || level.Value == Level.B_Level || !useTmaInsteadOfTsa) 
            {
                verifier = DataVerifierFactory.Create(level);
            }
            else
            {
                verifier = DataVerifierFactory.CreateFromTimemarkAuthority(level.Value, new CurrentTimemarkProvider());
            }

            SignatureSecurityInformation result = verifier.Verify(output);
            Console.WriteLine(result.ToString());

            
            Assert.AreEqual(validationStatus, result.ValidationStatus);
            Assert.AreEqual(trustStatus, result.TrustStatus);
            Assert.AreEqual(authCert.Thumbprint, result.Signer.Thumbprint);
            Assert.AreEqual((level & Level.T_Level) == Level.T_Level, result.TimestampRenewalTime > DateTime.UtcNow);
            Assert.NotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
        }

        private void VerifyOnlyFromTma(Stream output)
        {
            IDataVerifier verifier;
            if (!level.HasValue || level.Value == Level.B_Level || !useTmaInsteadOfTsa)
            {
                verifier = DataVerifierFactory.Create(level);
            }
            else
            {
                verifier = DataVerifierFactory.CreateFromTimemarkAuthority(level.Value, new CurrentTimemarkProvider());
            }

            SignatureSecurityInformation result = verifier.Verify(output);
            Console.WriteLine(result.ToString());


            Assert.AreEqual(validationStatus, result.ValidationStatus);
            Assert.AreEqual(trustStatus, result.TrustStatus);
            Assert.AreEqual(authCert.Thumbprint, result.Signer.Thumbprint);
            Assert.IsNull(result.TimestampRenewalTime);
            Assert.NotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
        }

        private void VerifyOnlyAsTma(Stream output)
        {
            TimemarkKey key;
            ITmaDataVerifier verifier = DataVerifierFactory.CreateAsTimemarkAuthority(level.Value);

            SignatureSecurityInformation result = verifier.Verify(output, DateTime.UtcNow, out key);
            Console.WriteLine(result.ToString());

            Assert.NotNull(key.SignatureValue);
            Assert.AreEqual(key.Signer.Thumbprint, result.Signer.Thumbprint);
            Assert.IsTrue((DateTime.UtcNow - key.SigningTime) < new TimeSpan(0, 1, 0));


            Assert.AreEqual(validationStatus, result.ValidationStatus);
            Assert.AreEqual(trustStatus, result.TrustStatus);
            Assert.AreEqual(authCert.Thumbprint, result.Signer.Thumbprint);
        }

        private void UnsealAndVerify(Stream output)
        {
            IDataUnsealer unsealer;
            if (!level.HasValue || level.Value == Level.B_Level || !useTmaInsteadOfTsa) 
            {
                unsealer = DataUnsealerFactory.Create(both, level);
            }
            else 
            {
                unsealer = DataUnsealerFactory.CreateFromTimemarkAuthority(both, level.Value, new CurrentTimemarkProvider());
            }
            
            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            MemoryStream stream = new MemoryStream();
            Utils.Copy(result.UnsealedData, stream);
            result.UnsealedData.Close();

            Assert.IsTrue((DateTime.UtcNow - result.SealedOn) < new TimeSpan(0, 1, 0));
            Assert.IsNotNull(result.SignatureValue);
            Assert.AreEqual(validationStatus, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(trustStatus, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(authCert.Thumbprint, result.AuthenticationCertificate.Thumbprint);
            Assert.AreEqual(signCert == null ? authCert.Thumbprint : signCert.Thumbprint, result.SigningCertificate.Thumbprint);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(clearMessage, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        private Stream Seal()
        {
            IDataSealer sealer;
            if (!level.HasValue || level.Value == Level.B_Level)
            {
                sealer = DataSealerFactory.Create(authCert, signCert, level == null ? Level.B_Level : level.Value);
            }
            else
            {
                if (useTmaInsteadOfTsa)
                    sealer = DataSealerFactory.CreateForTimemarkAuthority(authCert, signCert, level.Value);
                else
                    sealer = DataSealerFactory.Create(authCert, signCert, level.Value, tsa);
            }

            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(clearMessage)), bobEtk);
            return output;
        }

        private static X509Certificate2 AskCertificate(X509KeyUsageFlags flags)
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection nonRep = my.Certificates.Find(X509FindType.FindByKeyUsage, flags, true);
                return X509Certificate2UI.SelectFromCollection(nonRep, "Select your cert", "Select the cert you want to used to sign the msg", X509SelectionFlag.SingleSelection)[0];
            }
            finally
            {
                my.Close();
            }
        }


    }
}
