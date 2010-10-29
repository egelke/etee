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

using Siemens.EHealth.Etee.Crypto.Decrypt;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using System.Diagnostics;
using System.IO;
using System;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    
    
    /// <summary>
    ///This is a test class for VerifierTest and is intended
    ///to contain all VerifierTest Unit Tests
    ///</summary>
    [TestClass()]
    public class VerifierTest
    {
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


        [TestMethod]
        [Description("Verifies a valid certificate with rsa key-pair")]
        public void VerifyNormal()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            Assert.IsNull(info.IssuerInfo);
        }

        [TestMethod]
        [Description("Verifies a valid certificate with dsa key-pair")]
        public void VerifyDsa()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\dsacert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            Assert.IsNull(info.IssuerInfo);

        }

        [TestMethod]
        [Description("Verifies a valid certificate for signature and other usages")]
        public void VerifyMultiKeyUsage()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\musagecert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            Assert.IsNull(info.IssuerInfo);
        }

        [TestMethod]
        [Description("Verifies a invalid certificate with rsa key for 1024")]
        public void VerifyKeySize()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\keysizecert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(result.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

        [TestMethod]
        [Description("Verifies a invalid certificate with dsa key for 1024")]
        public void VerifyDsaKeySize()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\dsasizecert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(result.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }
        

        [TestMethod]
        [Description("Verifies a invalid certificate that is revoked")]
        public void VerifyRevoked()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\revokedcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.Revoked));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            Assert.IsNull(info.IssuerInfo);
        }

        [TestMethod]
        [Description("Verifies a valid certificate but with revoked issuer")]
        public void VerifyRevokedInt()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int_revoked\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown)); //therefore the validation status is unsure
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.Revoked));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            Assert.IsNull(info.IssuerInfo);
        }

        
        [TestMethod]
        public void Partial()
        {
            X509Certificate2 cert = new X509Certificate2("untrustedRoot\\int\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize)); //therefore the validation status is Invalid
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Unsure, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown)); //therefore the validation status is unsure
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.IssuerTrustUnknown));

            Assert.IsNull(info.IssuerInfo);
        }

        [TestMethod]
        public void Untrusted()
        {
            X509Certificate2 cacert = new X509Certificate2("untrustedRoot\\cacert.pem");

            X509Certificate2 cert = new X509Certificate2("untrustedRoot\\int\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.VerifyInternal(DotNetUtilities.FromX509Certificate(cert), new X509Certificate2Collection(cacert), DateTime.Now);

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize)); //therefore the validation status is Invalid
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedRoot));
            Assert.IsNull(info.IssuerInfo);
        }
         
        
        [TestMethod]
        public void InvalidKeyUsage()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\iusagecert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(result.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

        [TestMethod]
        public void InvalidKeyUsageInt()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int_usageKey\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown)); //therefore the validation status is unsure
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidForUsage));

            //the rest of the chain is already checked
        }

        
        [TestMethod]
        public void InvalidBaseUsageInt()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int_usageBase\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotValidKeySize)); //therefore the validation status is invalid
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.InvalidBasicConstraints));

            //the rest of the chain is already checked
        }

        
        [TestMethod]
        public void InvalidSignature()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\isigncert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));
            

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

        [TestMethod]
        public void InvalidSignatureInt()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int_sign\\normalcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Unsure, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.None, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.RevocationStatusUnknown)); //therefore the validation status is unsure
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.UntrustedIssuer));

            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotSignatureValid));

            //the rest of the chain is already checked
        }

        [TestMethod]
        public void Expired()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\expiredcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));


            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

        [TestMethod]
        public void NotYetActive()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\nyacert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotTimeValid));


            info = info.IssuerInfo;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

        /*
        [TestMethod]
        public void PeriodNotNested()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int\\unnestedcert.pem");
            CertificateSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            CertificateSecurityInformation info = result;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.IsTrue(info.SecurityViolations.Contains(CertSecurityViolation.NotTimeNested));


            info = info.Origine;

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Valid, info.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.Full, info.TrustStatus);
            Assert.AreEqual<int>(0, info.SecurityViolations.Count);

            //the rest of the chain is already checked
        }

  
        [TestMethod]
        public void InvalidOverlapInt()
        {
            X509Certificate2 cert = new X509Certificate2("trustedRoot\\int_overlap2\\normalcert.pem");
            X509ChainSecurityInformation result = Verifier.Verify(DotNetUtilities.FromX509Certificate(cert));

            //check overall result
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.NoTrust, result.TrustStatus);
            Assert.IsTrue(result.SecurityViolations.Contains(SecurityViolation.NotSignatureValid));

            //check element in chain
            Assert.AreEqual<ValidationStatus>(ValidationStatus.Invalid, result.Elements[1].ValidationStatus);
            Assert.AreEqual<Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus>(Siemens.EHealth.Etee.Crypto.Decrypt.TrustStatus.NoTrust, result.Elements[1].TrustStatus);
            Assert.IsTrue(result.Elements[1].SecurityViolations.Contains(SecurityViolation.NotSignatureValid));
        }
         */

    }
}
