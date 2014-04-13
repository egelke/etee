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
using Egelke.EHealth.Etee.Crypto.Store;
using System.Diagnostics;
using Egelke.EHealth.Client.Pki;

namespace Egelke.eHealth.ETEE.Crypto.Test
{

    [TestFixture, Explicit, Category("Manual")]
    public class SelectCert
    {
        public TraceSource trace = new TraceSource("Egelke.EHealth.Etee.Test");

        const String clearMessage = "This is a secret message from Alice for Bob";

        static EHealthP12 ehCert;

        static String subject = "SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Authentication), C=BE";

        static String subject2 = "SERIALNUMBER=79021802145, G=Bryan Eduard, SN=Brouckaert, CN=Bryan Brouckaert (Signature), C=BE";

        static EHealthP12 alice;

        static EHealthP12 bob;

        static EncryptionToken bobEtk;

        static ITimestampProvider tsa;

        Level? level;

        bool useTmaInsteadOfTsa;

        ETEE::Status.TrustStatus trustStatus;

        ValidationStatus validationStatus;

        [TestFixtureSetUp]
        public static void InitializeClass()
        {
            //Bob as decryption
            bobEtk = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));

            //Bob (and Alice) used for decryption
            alice = new EHealthP12("../../alice/alices_private_key_store.p12", "test");
            bob = new EHealthP12("../../bob/bobs_private_key_store.p12", "test");

            //create a tsa (fedict in this case)
            tsa = new Rfc3161TimestampProvider();
        }

        [Test]
        public void NullLevel()
        {
            level = null;
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

        [Test]
        public void B_Level()
        {
            level = Level.B_Level;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("B-Level: Sealing");
            Stream output = Seal();

            trace.TraceInformation("B-Level: Verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("B-Level: Unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void T_Level()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("T-Level: Sealing");
            Stream output = Seal();

            trace.TraceInformation("T-Level: Verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("T-Level: Unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void T_LevelTma()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("T-Level TMA: Seal");
            Stream output = Seal();

            trace.TraceInformation("T-Level TMA: Verify from TMA");
            VerifyFromTma(output);

            output.Position = 0;

            trace.TraceInformation("T-Level TMA: Verify as TMA");
            VerifyAsTma(output);

            output.Position = 0;

            trace.TraceInformation("T-Level TMA: Unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LT_Level()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("LT-Level: seal");
            Stream output = Seal();

            trace.TraceInformation("LT-Level: verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level: unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LT_LevelIn2Steps()
        {
            level = Level.B_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("B-Level: seal");
            Stream output = Seal();

            trace.TraceInformation("LT-Level: complete");
            level = Level.LT_Level;
            output = Complete(output);

            trace.TraceInformation("LT-Level: verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level: unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LT_LevelIn3Steps()
        {
            level = Level.B_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("B-Level: seal");
            Stream output = Seal();

            trace.TraceInformation("T-Level: complete");
            level = Level.T_Level;
            output = Complete(output);

            trace.TraceInformation("LT-Level: complete");
            level = Level.LT_Level;
            output = Complete(output);

            trace.TraceInformation("LT-Level: verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level: unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LT_LevelTma()
        {
            level = Level.LT_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("LT-Level TMA: Seal");
            Stream output = Seal();

            trace.TraceInformation("LT-Level TMA: Verify from TMA");
            VerifyFromTma(output);

            output.Position = 0;
            
            trace.TraceInformation("LT-Level TMA: Verify as TMA");
            VerifyAsTma(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level TMA: unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LT_LevelTmaIn2Steps()
        {
            level = Level.B_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("B-Level TMA: Seal");
            Stream output = Seal();

            trace.TraceInformation("LT-Level: complete for TMA");
            level = Level.LT_Level;
            output = Complete(output);

            trace.TraceInformation("LT-Level TMA: Verify from TMA");
            VerifyFromTma(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level TMA: Verify as TMA");
            VerifyAsTma(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level TMA: unseal");
            Unseal(output);

            output.Close();
        }

        [Test]
        public void LTA_Level()
        {
            level = Level.LTA_Level;
            useTmaInsteadOfTsa = false;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("LTA-Level: seal");
            Stream output = Seal();

            trace.TraceInformation("LT-Level: verify");
            Verify(output);

            output.Position = 0;

            trace.TraceInformation("LT-Level: unseal");
            Unseal(output);

            output.Close();
        }

        

        [Test]
        public void LTA_LevelTma()
        {
            level = Level.LTA_Level;
            useTmaInsteadOfTsa = true;
            validationStatus = ValidationStatus.Valid;
            trustStatus = EHealth.Etee.Crypto.Status.TrustStatus.Full;

            trace.TraceInformation("LTA-Level TMA: seal");
            Stream output = Seal();

            trace.TraceInformation("LTA-Level TMA: Verify from TMA");
            VerifyFromTma(output);

            output.Position = 0;

            trace.TraceInformation("LTA-Level TMA: Verify as TMA");
            VerifyAsTma(output);

            output.Position = 0;

            trace.TraceInformation("LTA-Level TMA: unseal");
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
            Assert.AreEqual(subject, result.Signer.Subject);
            Assert.AreEqual((level & Level.T_Level) == Level.T_Level, result.TimestampRenewalTime > DateTime.UtcNow);
            Assert.NotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
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
            Assert.AreEqual(subject, result.Signer.Subject);
            Assert.IsNull(result.TimestampRenewalTime);
            Assert.NotNull(result.SignatureValue);
            Assert.IsTrue((DateTime.UtcNow - result.SigningTime) < new TimeSpan(0, 1, 0));
        }

        private void VerifyAsTma(Stream output)
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
            Assert.AreEqual(subject, result.Signer.Subject);
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
            Utils.Copy(result.UnsealedData, stream);
            result.UnsealedData.Close();

            Assert.IsTrue((DateTime.UtcNow - result.SealedOn) < new TimeSpan(0, 1, 0));
            Assert.IsNotNull(result.SignatureValue);
            Assert.AreEqual(validationStatus, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(trustStatus, result.SecurityInformation.TrustStatus);
            Assert.AreEqual(subject, result.AuthenticationCertificate.Subject);
            Assert.AreEqual(subject2, result.SigningCertificate.Subject);
            Assert.AreEqual(bob["825373489"].Thumbprint, result.SecurityInformation.Encryption.Subject.Certificate.Thumbprint);
            Assert.AreEqual(clearMessage, Encoding.UTF8.GetString(stream.ToArray()));
            Assert.IsNotNull(result.SecurityInformation.ToString());
        }

        private Stream Seal()
        {
            IDataSealer sealer;
            if (!level.HasValue || level.Value == Level.B_Level)
            {
                if (ehCert != null)
                {
                    sealer = EhDataSealerFactory.Create(level == null ? Level.B_Level : level.Value, ehCert);
                }
                else
                {
                    sealer = EidDataSealerFactory.Create(level == null ? Level.B_Level : level.Value, new TimeSpan(0, 5, 0));
                }
            }
            else
            {
                if (ehCert != null)
                {
                    if (useTmaInsteadOfTsa)
                        sealer = EhDataSealerFactory.CreateForTimemarkAuthority(level.Value, ehCert);
                    else
                        sealer = EhDataSealerFactory.Create(level.Value, tsa, ehCert);
                }
                else
                {
                    if (useTmaInsteadOfTsa)
                        sealer = EidDataSealerFactory.CreateForTimemarkAuthority(level.Value, new TimeSpan(0, 5, 0));
                    else
                        sealer = EidDataSealerFactory.Create(level.Value, tsa, new TimeSpan(0, 5, 0));
                }
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
