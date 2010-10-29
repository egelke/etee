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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Etee.Crypto;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using Org.BouncyCastle.Cms;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for EncryptionTokenTest
    /// </summary>
    [TestClass]
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
        
        [TestMethod]
        public void Bob()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("bobs_public_key.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));
            
            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void Alice()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("alices_public_key.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void ValidButScrambledDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("valid_but_scrambledDN.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));


            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.SenderTrustUnknown));
            Assert.IsTrue(info.Signature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(info.Signature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.TokenTrustUnknown));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        [ExpectedException(typeof(CmsException))]
        public void EncorrectEncoding()
        {
            new EncryptionToken(Utils.ReadFully("incorrectly_encoded.etk"));
        }

        [TestMethod]
        public void DifferentDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("auth_and_encr_not_same_DN.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.HasNotPermittedNameConstraint));
        }

        [TestMethod]
        public void ExpiredEnc()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("expired_encr.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void ExpiredAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("expired_auth.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
           // Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void NotYetAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("not_yet_auth.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void InvalidEncKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("invalid_encrkey_usage.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [TestMethod]
        public void InvalidAuthKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("invalid_authkey_usage.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [TestMethod]
        public void InvalidKeySize()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("invalid_key_size.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }

        [TestMethod]
        public void InvalidChain()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("invalid_cert_chain.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            //Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.InvalidSignature));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
        }


        [TestMethod]
        public void MixedKeyAlgorithm()
        {
            //In contradiction with its name, it is allowed because it has RSA for encryption and DSA for signing
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("invalid_key_algorithm.etk"));
            EtkSecurityInformation info = receiver.Verify();

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual<TrustStatus>(TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.IsTrue(info.Sender.Subject.Contains("CN=ETK-RA"));

            Assert.IsTrue(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedToken));
            Assert.IsFalse(info.SecurityViolations.Contains(EtkSecurityViolation.UntrustedSender));
            Assert.IsTrue(info.TokenInformation.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.TokenInformation.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize)); //this is why it is invailid, not because of the key type
        }
    }
}
