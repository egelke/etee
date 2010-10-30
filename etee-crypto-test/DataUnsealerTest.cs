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
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Siemens.EHealth.Etee.Crypto;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class DataUnsealerTest
    {

        private static X509Certificate2 bobEnc;

        private static X509Certificate2 bobAuth;

        private static X509Certificate2 aliceEnc;

        private static X509Certificate2 aliceAuth;

        private static X509Certificate2 dirkEnc;

        private static X509Certificate2 dirkAuth;

        private static X509Certificate2 nialaEnc;

        private static X509Certificate2 nialaAuth;

        private static X509Certificate2 niala2Enc;

        private static X509Certificate2 niala2Auth;

        private static X509Certificate2 niala3Enc;

        private static X509Certificate2 niala3Auth;

        private static X509Certificate2 niala4Enc;

        private static X509Certificate2 niala4Auth;

        private static X509Certificate2 oldHospEnc;

        private static X509Certificate2 oldHospAuth;

        private static X509Certificate2 hospEnc;

        private static X509Certificate2 hospAuth;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext) {
            bobAuth = new X509Certificate2("users/bob_auth.p12", "test", X509KeyStorageFlags.Exportable);
            bobEnc = new X509Certificate2("users/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);
            aliceAuth = new X509Certificate2("users/alice_auth.p12", "test", X509KeyStorageFlags.Exportable);
            aliceEnc = new X509Certificate2("users/alice_enc.p12", "test", X509KeyStorageFlags.Exportable);
            dirkAuth = new X509Certificate2("users/dirk_auth.p12", "test", X509KeyStorageFlags.Exportable);
            dirkEnc = new X509Certificate2("users/dirk_enc.p12", "test", X509KeyStorageFlags.Exportable);
            nialaAuth = new X509Certificate2("users/niala_auth.p12", "test", X509KeyStorageFlags.Exportable);
            nialaEnc = new X509Certificate2("users/niala_enc.p12", "test", X509KeyStorageFlags.Exportable);
            niala2Auth = new X509Certificate2("users/niala2_auth.p12", "test", X509KeyStorageFlags.Exportable);
            niala2Enc = new X509Certificate2("users/niala2_enc.p12", "test", X509KeyStorageFlags.Exportable);
            niala3Auth = new X509Certificate2("users/niala3_auth.p12", "test", X509KeyStorageFlags.Exportable);
            niala3Enc = new X509Certificate2("users/niala3_enc.p12", "test", X509KeyStorageFlags.Exportable);
            niala4Auth = new X509Certificate2("users/niala4_auth.p12", "test", X509KeyStorageFlags.Exportable);
            niala4Enc = new X509Certificate2("users/niala4_enc.p12", "test", X509KeyStorageFlags.Exportable);
            oldHospAuth = new X509Certificate2("users/oldHospital_auth.p12", "test", X509KeyStorageFlags.Exportable);
            oldHospEnc = new X509Certificate2("users/oldHospital_enc.p12", "test", X509KeyStorageFlags.Exportable);
            hospAuth = new X509Certificate2("users/hospital_auth.p12", "test", X509KeyStorageFlags.Exportable);
            hospEnc = new X509Certificate2("users/hospital_enc.p12", "test", X509KeyStorageFlags.Exportable);
        }

        private IDataUnsealer unsealer;

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void Clear()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            FileStream fs = new FileStream("clear.txt", FileMode.Open);
            using (fs)
            {
                UnsealResult result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void SignedEncryptedOnly()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            FileStream fs = new FileStream("openssl_encrypted.msg", FileMode.Open);
            using (fs)
            {
                UnsealResult result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void SignedOnly()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            FileStream fs = new FileStream("openssl_inner_signed.msg", FileMode.Open);
            using (fs)
            {
            UnsealResult result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void InvalidAlgo()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("openssl_outer_signed.msg", FileMode.Open);
            using (fs)
            {
                result = unsealer.Unseal(fs);
            }

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData)); //Invalid signature results in invalid data (since we aren't 100% sure)
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
        }

        [TestMethod]
        public void InvalidAlgoBigFile()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("openssl_outer_signed_big.msg", FileMode.Open);
            using (fs)
            {
                result = unsealer.Unseal(fs);
            }

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData)); //Invalid signature results in invalid data (since we aren't 100% sure)
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
        }

        [TestMethod]
        public void eid()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_both_eid_certs_signed.msg", FileMode.Open);
            using (fs)
            {
                result = unsealer.Unseal(fs);
            }

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData)); //Invalid signature results in invalid data (since we aren't 100% sure)
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject)); //We don't have the issues, so untrusted
        }

        [TestMethod]
        public void eidExpired()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_both_expired_eid_certs_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData)); //Invalid signature results in invalid data (since we aren't 100% sure)
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        //[TestMethod]
        //No need to execute this test, revocation of local crl not supported in .Net library
        public void eidRevoked()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_both_revoked_eid_certs_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        //[TestMethod]
        //No need to execute this test, revocation of local crl not supported in .Net library
        public void eidSuspended()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_both_suspended_eid_certs_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        //[TestMethod]
        //Crl validation tested seperately
        public void eidNoCrlUri()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_certs_contain_no_crluri.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        //[TestMethod]
        //Crl validation tested seperately
        public void eidNonExistingCrlUri()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_certs_contain_noexisting_crluri.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void Correct()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_correct.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual<String>("this is a test message for a correctly triple wrapped message", clear);
        }

        [TestMethod]
        public void crossSigned()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_cross_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.InnerSignature.ValidationStatus);
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        //[TestMethod]
        //Disabled, inner signature is completely *** up
        public void ExpiredAuth()
        {
            unsealer = DataUnsealerFactory.Create(nialaEnc, nialaAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_expired_auth.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void ExpiredEnc()
        {
            unsealer = DataUnsealerFactory.Create(niala2Enc, niala2Auth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_expired_encr.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.Encryption.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            Assert.AreEqual<String>("this is test message that is wrapped with wrong parameters", clear);
        }

        [TestMethod]
        public void InvalidCertChain()
        {
            unsealer = DataUnsealerFactory.Create(niala3Enc, niala3Auth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_cert_chain.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.Encryption.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void InvalidCmsSigned()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_cms_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void InvalidEncrypted()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_encrypted.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void InvalidInnerSigned()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_inner_signed.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void InvalidKeySize()
        {
            unsealer = DataUnsealerFactory.Create(oldHospEnc, oldHospAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_key_size.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.Encryption.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        public void InvalidKeyUsage()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_key_usage.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        public void InvalidSignature()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_invalid_signature.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void InvalidMultiSignTimes()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_more_signing_times.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void MultiRecipients()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_multi_recipients.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        public void NotValidYet()
        {
            unsealer = DataUnsealerFactory.Create(niala4Enc, niala4Auth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_not_valid_yet_auth.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            Assert.AreEqual<String>("this is the message content", clear);
        }

        //[TestMethod]
        //Crl validation tested seperately
        public void Revoked()
        {
            unsealer = DataUnsealerFactory.Create(dirkEnc, dirkAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_revoked_cert.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void DsaSignatureWithRsaKey()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_signed_with_other_key_and_algo.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void UnauthorizedAlgos()
        {
            unsealer = DataUnsealerFactory.Create(hospEnc, hospAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_unauthorized_algos.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm));
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.NotAllowedEncryptionAlgorithm));
            //Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.NotAllowedKeyEncryptionAlgorithm)); //Key is RSA, so allowed
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm));
            Assert.AreEqual<String>("use invalid algos", clear);
        }

        [TestMethod]
        public void UnsupportedAlgos()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_unsupported_algos.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm));
            Assert.AreEqual<String>("use unsupported signature algos", clear);
        }

        //[TestMethod]
        //Pitty, don't have private decryption key
        public void WasNotValidYet()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_was_not_valid_yet_auth.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(NotSupportedException))]
        public void MultiSigned()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_with_2_signerinfos.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        //[TestMethod]
        //Not a tripled wrapped message and signed multiple times
        public void WithoutCerts()
        {
            unsealer = DataUnsealerFactory.Create(niala4Enc, niala4Auth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_without_certset.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }
        }

        [TestMethod]
        public void InvalidInnerSignature()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_without_inner_eid_cert.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        public void MissingOuterCertificate()
        {
            unsealer = DataUnsealerFactory.Create(bobEnc, bobAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_without_outer_eid_cert.msg", FileMode.Open);
            using (fs)
            {
                 result = unsealer.Unseal(fs);
            }

            byte[] data = new byte[result.UnsealedData.Length];
            result.UnsealedData.Read(data, 0, data.Length);
            String clear = Encoding.UTF8.GetString(data);

            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(EHealth.Etee.Crypto.Decrypt.TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.DataValidationImpossible));
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotFoundSigner));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
            Assert.AreEqual<String>("this is an ehealth test message", clear);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidMessageException))]
        public void WrongEncryption()
        {
            unsealer = DataUnsealerFactory.Create(aliceEnc, aliceAuth);
            UnsealResult result;
            FileStream fs = new FileStream("triple_wrapped_wrong_encryption_key.msg", FileMode.Open);
            using (fs)
            {
                result = unsealer.Unseal(fs);
            }
        }
    }
}
