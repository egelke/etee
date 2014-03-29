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

using Egelke.EHealth.Etee.Crypto;
using Org.BouncyCastle.Cms;
using NUnit.Framework;
using ETEE = Egelke.EHealth.Etee.Crypto;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Etee.Crypto.Status;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for EncryptionTokenTest
    /// </summary>
    [TestFixture]
    public class EncryptionTokenTest
    {

        X509Certificate2 testCA;

        [TestFixtureSetUp]
        public void SetUp()
        {
            testCA = new X509Certificate2("../../imports/CA.cer");

            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (!store.Certificates.Contains(testCA))
                {
                    store.Add(testCA);
                }
            }
            finally
            {
                store.Close();
            }
        }

        [TestFixtureTearDown]
        public void TearDown()
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (store.Certificates.Contains(testCA))
                {
                    store.Remove(testCA);
                }
            }
            finally
            {
                store.Close();
            }
        }

        private void LoadNewCert(X509Store store, String certPath)
        {
            X509Certificate2 cert = new X509Certificate2(certPath);
            X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (found.Count == 0)
            {
                store.Add(cert);
            }
        }

        [Test]
        public void kgss()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/kgss.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);
        }
        
        [Test]
        public void Bob()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../bob/bobs_public_key.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void Bob2()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/Bob2_public_key.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void Bob3()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/Bob3_public_key.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void Alice()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../alice/alices_public_key.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [Test]
        public void ValidButScrambledDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/valid_but_scrambledDN.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
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
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.HasNotPermittedNameConstraint));
        }

        [Test]
        public void ExpiredEnc()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/expired_encr.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void ExpiredAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/expired_auth.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void NotYetAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/not_yet_auth.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [Test]
        public void InvalidEncKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_encrkey_usage.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [Test]
        public void InvalidAuthKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_authkey_usage.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [Test]
        public void InvalidKeySize()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_key_size.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
            //This is no longer the case because we allow eID with 1024 bit keys.
            //Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }

        [Test]
        public void InvalidChain()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_cert_chain.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.IssuerInfo.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.UntrustedRoot));
        }


        [Test]
        public void MixedKeyAlgorithm()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("../../etk/invalid_key_algorithm.etk"));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeyType)); //this is why it is invailid, not because of the key type
        }
    }
}
