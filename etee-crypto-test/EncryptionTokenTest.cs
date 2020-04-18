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
using ETEE = Egelke.EHealth.Etee.Crypto;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Etee.Crypto.Status;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    /// <summary>
    /// Summary description for EncryptionTokenTest
    /// </summary>
    [TestClass]
    public class EncryptionTokenTest
    {
   
        private static string _basePath = Path.GetDirectoryName(typeof(Alice).Assembly.Location);
        private static string GetAbsoluteTestFilePath(string relativePath) => Path.Combine(_basePath, relativePath);

        private void LoadNewCert(X509Store store, String certPath)
        {
            X509Certificate2 cert = new X509Certificate2(certPath);
            X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (found.Count == 0)
            {
                store.Add(cert);
            }
        }

        [TestMethod]
        public void kgss()
        {
            if (DateTime.Now > new DateTime(2015, 4, 22)) Assert.Inconclusive("KGSS token must be updated");

            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/kgss.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);
        }
        
        [TestMethod]
        public void Bob()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("bob/bobs_public_key.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void Bob2()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/Bob2_public_key.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void Bob3()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/Bob3_public_key.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void Alice()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("alice/alices_public_key.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void ValidButScrambledDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/valid_but_scrambledDN.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [TestMethod]
        public void IncorrectEncoding()
        {
            Assert.ThrowsException<CmsException>(() => new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/incorrectly_encoded.etk"))));
        }

        [TestMethod]
        public void DifferentDN()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/auth_and_encr_not_same_DN.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            //Assert.AreEqual(ValidationStatus.Unsure, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.InvalidBasicConstraints));
        }

        [TestMethod]
        public void ExpiredEnc()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/expired_encr.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.Unsure, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void ExpiredAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/expired_auth.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void NotYetAuth()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/not_yet_auth.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void InvalidEncKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/invalid_encrkey_usage.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [TestMethod]
        public void InvalidAuthKeyUsage()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/invalid_authkey_usage.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
        }

        [TestMethod]
        public void InvalidKeySize()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/invalid_key_size.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Invalid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
            //This is no longer the case because we allow eID with 1024 bit keys.
            //Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }

        [TestMethod]
        public void InvalidChain()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/invalid_cert_chain.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.IssuerInfo.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.UntrustedRoot));
        }


        [TestMethod]
        public void MixedKeyAlgorithm()
        {
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully(GetAbsoluteTestFilePath("etk/invalid_key_algorithm.etk")));
            CertificateSecurityInformation info = receiver.Verify();
            Console.WriteLine(info.ToString());

            Assert.IsNotNull(info.ToString());
            Assert.AreEqual(ETEE::Status.TrustStatus.None, info.TrustStatus);
            Assert.AreEqual(ValidationStatus.Valid, info.ValidationStatus);

            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(info.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }
    }
}
