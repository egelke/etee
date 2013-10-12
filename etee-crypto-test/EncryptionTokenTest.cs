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

using Siemens.EHealth.Etee.Crypto;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using Org.BouncyCastle.Cms;
using NUnit.Framework;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for EncryptionTokenTest
    /// </summary>
    [TestFixture]
    public class EncryptionTokenTest
    {
        public EncryptionTokenTest()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        public void dummy()
        {

        }
        
        [Test]
        public void Bob()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/bobs_public_key.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));
            
            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void Alice()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/alices_public_key.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void ValidButScrambledDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/valid_but_scrambledDN.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));


            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        [ExpectedException(typeof(CmsException))]
        public void EncorrectEncoding()
        {
            new EncryptionToken(Utils.ReadFully("../../etk/incorrectly_encoded.etk"));
        }

        [Test]
        public void DifferentDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/auth_and_encr_not_same_DN.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.HasNotPermittedNameConstraint));
        }

        [Test]
        public void ExpiredEnc()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/expired_encr.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void ExpiredAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/expired_auth.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
           // Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void NotYetAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/not_yet_auth.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void InvalidEncKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_encrkey_usage.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [Test]
        public void InvalidAuthKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_authkey_usage.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [Test]
        public void InvalidKeySize()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_key_size.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }

        [Test]
        public void InvalidChain()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_cert_chain.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
        }


        [Test]
        public void MixedKeyAlgorithm()
        {
            //In contradiction with its name, it is allowed because it has RSA for encryption and DSA for signing
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_key_algorithm.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedSender));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize)); //this is why it is invailid, not because of the key type
        }
    }
}
