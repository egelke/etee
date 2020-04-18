﻿using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class TestMessages
    {
        private static string _basePath = Path.GetDirectoryName(typeof(Alice).Assembly.Location);
        private static string GetAbsoluteTestFilePath(string relativePath) => Path.Combine(_basePath, relativePath);

        private IDataUnsealer nullUnsealer = DataUnsealerFactory.Create(null,
            new EHealthP12(GetAbsoluteTestFilePath("alice/alices_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/old_bobs_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bobs_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bob2_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bob3_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("dirk/dirks_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/expired_auth.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/expired_encr.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_authkey_usage.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_encrkey_usage.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_cert_chain.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_key_algorithm.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_key_size.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/not_yet_auth.p12"), "test"));

        private IDataUnsealer bUnsealer = DataUnsealerFactory.Create(Level.B_Level,
            new EHealthP12(GetAbsoluteTestFilePath("alice/alices_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/old_bobs_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bobs_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bob2_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("bob/bob3_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("dirk/dirks_private_key_store.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/expired_auth.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/expired_encr.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_authkey_usage.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_encrkey_usage.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_cert_chain.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_key_algorithm.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/invalid_key_size.p12"), "test"),
            new EHealthP12(GetAbsoluteTestFilePath("other/not_yet_auth.p12"), "test"));

        [TestMethod]
        public void BrokenSignedData()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/brokenSignedData.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = bUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void Clear()
        {
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/clear.txt"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => bUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void BothEidCertsSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_both_eid_certs_signed.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void BothEidCertsSignedV21()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/SEALED_WITH_EID_OCSP_NONE.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
        }

        [TestMethod]
        public void BothExiredEidCertsSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_both_expired_eid_certs_signed.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod, Ignore("OCSP service no longer available")]
        public void BothRevokedEidCertsSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_both_revoked_eid_certs_signed.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.Revoked));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.Revoked));
        }

        [TestMethod,  Ignore("OCSP service no longer available")]
        public void BothSuspendedEidCertsSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_both_suspended_eid_certs_signed.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.Revoked));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.Revoked));
        }

        [TestMethod]
        public void CertsContainNoCrlUri()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_certs_contain_no_crluri.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            //already expired, so no need to do the check
            //Assert.AreEqual(TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            //Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.SenderTrustUnknown));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void CertsContainNonExistingCrlUri()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_certs_contain_noexisting_crluri.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            //already expired, so no need to do the check
            //Assert.AreEqual(TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            //Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.SenderTrustUnknown));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.SubjectTrustUnknown));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown));
        }

        [TestMethod]
        public void Correct()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_correct.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
            Assert.IsTrue(result.IsNonRepudiatable);
        }

        [TestMethod]
        public void CrossSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_cross_signed.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.InnerSignature.SecurityViolations.Contains(SecurityViolation.SubjectDoesNotMachEnvelopingSubject));
        }

        [TestMethod]
        public void ExpiredAuth()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_expired_auth.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void ExpiredEncr()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_expired_encr.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));
        }

        [TestMethod]
        public void InvalidCertChain()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_cert_chain.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.IssuerInfo.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
        }

        [TestMethod]
        public void InvalidCmsSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_cms_signed.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void InvalidEncrypted()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_encrypted.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void InvalidInnerSigned()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_inner_signed.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void InvalidKeySize()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_key_size.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.None, result.SecurityInformation.TrustStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedRecipient));
            Assert.IsTrue(result.SecurityInformation.Encryption.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            Assert.IsTrue(result.SecurityInformation.Encryption.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));
        }

        [TestMethod]
        public void InvalidKeyUsage()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_key_usage.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.Unsure, result.SecurityInformation.TrustStatus);

            //Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.UntrustedSender));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.UntrustedSubject));
            //Assert.IsTrue(result.SecurityInformation.OuterSignature.Subject.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));
            Assert.IsFalse(result.IsNonRepudiatable);
        }

        [TestMethod]
        public void InvalidSignature()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_invalid_signature.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
        }

        [TestMethod]
        public void InvalidMoreSigningTimes()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_more_signing_times.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException< InvalidMessageException > (() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void MultiRecipients()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_multi_recipients.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.AreEqual(TrustStatus.Unsure, result.SecurityInformation.TrustStatus);
        }

        [TestMethod,  Ignore("Doesn't find the decryption certificate because of incorrect issuer")]
        public void NotValidYetAuth()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_not_valid_yet_auth.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            //???
        }

        [TestMethod,  Ignore("The certificate chain is invalid, the revocation information isn't found")]
        public void RevokedCert()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_revoked_cert.msg"), FileMode.Open);
            using (file)
            {
                result = bUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            //???
        }

        [TestMethod]
        public void SignedWithOtherKeyAndAlgo()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_signed_with_other_key_and_algo.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);

            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
        }

        [TestMethod,  Ignore("Missing p12 with 'CN=Has unauthorized algos, OU=NIHII\\=723456123456'")]
        public void UnauthorizedAlgos()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_unauthorized_algos.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            //??
        }

        [TestMethod]
        public void UnsupportedAlgosSHA224WITHRSA()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_unsupported_algos_SHA224WITHRSA.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            Assert.AreEqual(ValidationStatus.Invalid, result.SecurityInformation.ValidationStatus);
            Assert.IsTrue(result.SecurityInformation.SecurityViolations.Contains(UnsealSecurityViolation.InvalidData));
            Assert.IsTrue(result.SecurityInformation.OuterSignature.SecurityViolations.Contains(SecurityViolation.NotAllowedSignatureDigestAlgorithm));
        }

        [TestMethod,  Ignore(@"Missing p12 with '37986951857310355882683937081880734299 (CN=Bob\,\,NIHII\=00000000202,OU=NIHII\=00000000202,OU=Bob,OU=eHealth-platform Belgium,O=Federal Government,C=BE)'")]
        public void WasNotValidYetAuth()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_was_not_valid_yet_auth.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);


            //???
        }

        [TestMethod]
        public void With2SignerInfos()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_with_2_signerinfos.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod]
        public void WithoutOuterCert()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_without_outer_cert.msg"), FileMode.Open);
            using (file)
            {
                Assert.ThrowsException<InvalidMessageException>(() => result = nullUnsealer.Unseal(file));
            }
        }

        [TestMethod,  Ignore("The text decrypts fines, so the right key is used.")]
        public void WrongEncryptionKey()
        {
            UnsealResult result;
            FileStream file = new FileStream(GetAbsoluteTestFilePath("msg/triple_wrapped_wrong_encryption_key.msg"), FileMode.Open);
            using (file)
            {
                result = nullUnsealer.Unseal(file);
            }
            System.Console.WriteLine(result.SecurityInformation);

            //???
        }

        
    }
}
