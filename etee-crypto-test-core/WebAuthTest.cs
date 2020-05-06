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
using Egelke.EHealth.Etee.Crypto.Status;
using System.Configuration;
using System.Collections.Specialized;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Security;
using Egelke.EHealth.Etee.Crypto.Store;
using System.Diagnostics;
using Egelke.EHealth.Client.Pki;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.eHealth.ETEE.Crypto.Test
{

    [TestClass]
    public class WebAuthTest
    {
        public TraceSource trace = new TraceSource("Egelke.EHealth.Etee.Test");

        const string clearMessage = "This is a secret message from Alice for Bob";

        static AsymmetricAlgorithm key;

        static EHealthP12 alice;
        static EHealthP12 bob;

        static EncryptionToken bobEtk;

        static ITimestampProvider tsa;

        Level? level;

        bool useTmaInsteadOfTsa;

        ETEE::Status.TrustStatus trustStatus;

        ValidationStatus validationStatus;

        [ClassInitialize]
        public static void InitializeClass(TestContext ctx)
        {
            //sign with generated key
            key = RSA.Create();

            //Bob as decryption
            bobEtk = new EncryptionToken(File.ReadAllBytes("bob/bobs_public_key.etk"));

            //Bob (and Alice) used for decryption
            alice = new EHealthP12("alice/alices_private_key_store.p12", "test");
            bob = new EHealthP12("bob/bobs_private_key_store.p12", "test");

            //create a tsa (fedict in this case)
            tsa = new Rfc3161TimestampProvider();
        }

        [TestMethod]
        public void NullLevel()
        {
            level = null;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("Null-Level: Sealing");
            Stream output = Seal();

            trace.TraceInformation("Null-Level: Verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("Null-Level: Unseal");
            Unseal(output);

            output.Close();
        }

        [TestMethod]
        public void B_Level()
        {
            level = Level.B_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("B-Level: Sealing");
            Stream output = Seal();

            using (var file = File.Create("web-levelB.cms"))
            {
                output.CopyTo(file);
                output.Position = 0;
            }

            trace.TraceInformation("B-Level: Verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("B-Level: Unseal");
            Unseal(output);

            output.Close();
        }


        private void Verify(Stream output)
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
            Assert.IsNull(result.Signer);
            //Assert.IsNotNull(result.SignerId);
            Assert.AreEqual((level & Level.T_Level) == Level.T_Level, result.TimestampRenewalTime > DateTime.UtcNow);
            Assert.IsNotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
            Assert.IsFalse(result.IsNonRepudiatable); //outer is never repudiatable
        }

        private void VerifyFromTma(Stream output)
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
            Assert.IsNull(result.Signer);
            Assert.IsNotNull(result.SignerId);
            Assert.IsNull(result.TimestampRenewalTime);
            Assert.IsNotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
            Assert.IsFalse(result.IsNonRepudiatable); //outer is never repudiatable
        }

        private void VerifyAsTma(Stream output)
        {
            TimemarkKey key;
            ITmaDataVerifier verifier = DataVerifierFactory.CreateAsTimemarkAuthority(level.Value);

            SignatureSecurityInformation result = verifier.Verify(output, DateTime.UtcNow, out key);
            Console.WriteLine(result.ToString());

            Assert.IsNotNull(key.SignatureValue);
            Assert.AreEqual(key.Signer.Thumbprint, result.Signer.Thumbprint);
            Assert.IsTrue((DateTime.UtcNow - key.SigningTime) < new TimeSpan(0, 1, 0));


            Assert.AreEqual(validationStatus, result.ValidationStatus);
            Assert.AreEqual(trustStatus, result.TrustStatus);
            Assert.IsNull(result.Signer);
            Assert.IsNotNull(result.SignerId);
            Assert.IsFalse(result.IsNonRepudiatable); //outer is never repudiatable
        }

        private void Unseal(Stream output)
        {
            IDataUnsealer unsealer;
            if (!level.HasValue || level.Value == Level.B_Level || !useTmaInsteadOfTsa) 
            {
                unsealer = DataUnsealerFactory.Create(level, alice, bob);
            }
            else 
            {
                unsealer = DataUnsealerFactory.CreateFromTimemarkAuthority(level.Value, new CurrentTimemarkProvider(), alice, bob);
            }
            
            UnsealResult result = unsealer.Unseal(output);
            Console.WriteLine(result.SecurityInformation.ToString());

            MemoryStream stream = new MemoryStream();
            result.UnsealedData.CopyTo(stream);
            result.UnsealedData.Close();

            Assert.IsTrue((DateTime.UtcNow - result.SealedOn) < new TimeSpan(0, 1, 0));
            Assert.IsNotNull(result.SignatureValue);
            Assert.AreEqual(validationStatus, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(trustStatus, result.SecurityInformation.TrustStatus);
            //Assert.AreEqual(subject, result.AuthenticationCertificate.Subject);
            //if (nonRepudiatable)
            //    Assert.AreEqual(subject2, result.SigningCertificate.Subject);
            //else
            //    Assert.AreEqual(subject, result.SigningCertificate.Subject);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(clearMessage, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        private Stream Seal()
        {
            IDataSealer sealer;
            if (!level.HasValue || level.Value == Level.B_Level)
            {
                sealer = DataSealerFactory.Create(level == null ? Level.B_Level : level.Value, key);
            }
            else
            {

                    if (useTmaInsteadOfTsa)
                        sealer = DataSealerFactory.CreateForTimemarkAuthority(level.Value, key);
                    else
                        sealer = DataSealerFactory.Create(level.Value, tsa, key);
            }

            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(clearMessage)), bobEtk);
            return output;
        }

        private Stream Complete(Stream toComplete)
        {
            IDataCompleter completer;
            if (useTmaInsteadOfTsa)
            {
                completer = DataCompleterFactory.CreateForTimeMarkAuthority(level.Value);
            }
            else
            {
                completer = DataCompleterFactory.Create(level.Value, tsa);
            }
            Stream output = completer.Complete(toComplete);
            return output;
        }
        


    }
}
