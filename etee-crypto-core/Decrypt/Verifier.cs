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
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Cms;
using BC = Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using System.Collections;
using Siemens.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Asn1.Cms;

namespace Siemens.EHealth.Etee.Crypto.Decrypt
{
    internal static class Verifier
    {

        private static void Translate(CertificateSecurityInformation dest, X509ChainElementEnumerator srcChain, bool partial)
        {
            X509ChainElement src = srcChain.Current;
            dest.Certificate = src.Certificate;

            foreach (X509ChainStatus status in src.ChainElementStatus)
            {
                switch (status.Status)
                {
                    case X509ChainStatusFlags.NoError:
                        //All ok, so nothing to do
                        break;
                    default:
                        try
                        {
                            dest.securityViolations.Add((CertSecurityViolation)Enum.Parse(typeof(CertSecurityViolation), Enum.GetName(typeof(X509ChainStatusFlags), status.Status)));
                        }
                        catch (ArgumentException ae)
                        {
                            throw new NotSupportedException("Unsupported Chain element status, please report this issue", ae);
                        }
                        break;
                }
            }

            if (srcChain.MoveNext())
            {
                dest.IssuerInfo = new CertificateSecurityInformation();
                Translate(dest.IssuerInfo, srcChain, partial);
            }
            else if (partial)
            {
                dest.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            }
        }

        public static CertificateSecurityInformation Verify(BC::X509Certificate encCert, BC::X509Certificate authCert)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            result.Certificate = new X509Certificate2(encCert.GetEncoded());

            //check validity
            try
            {
                encCert.CheckValidity();
            }
            catch (CertificateExpiredException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }
            catch (CertificateNotYetValidException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }

            //check key usage
            if (!encCert.GetKeyUsage()[2] || !encCert.GetKeyUsage()[3]) result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);

            //check issuer/subject
            if (!encCert.IssuerDN.Equivalent(encCert.SubjectDN, false)) result.securityViolations.Add(CertSecurityViolation.HasNotPermittedNameConstraint);

            //check key size
            if (!VerifyKeySize(encCert.GetPublicKey(), EteeActiveConfig.Unseal.MinimuumEncryptionKeySize.AsymmerticRecipientKey)) result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);

            //check key type
            if (!(encCert.GetPublicKey() is RsaKeyParameters)) result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);

            if (authCert != null)
            {
                //check signature
                try
                {
                    encCert.Verify(authCert.GetPublicKey());
                }
                catch (InvalidKeyException)
                {
                    result.securityViolations.Add(CertSecurityViolation.NotSignatureValid);
                }

                //check overlap
                /*
                 * The important part that the entire chain is valid now, not that one cert will be invalid before the other.
                try
                {
                    authCert.CheckValidity(encCert.NotBefore);
                    authCert.CheckValidity(encCert.NotAfter);
                }
                catch (CertificateExpiredException)
                {
                    result.securityViolations.Add(CertSecurityViolation.NotTimeNested);
                }
                catch (CertificateNotYetValidException)
                {
                    result.securityViolations.Add(CertSecurityViolation.NotTimeNested);
                }
                 */

                //Validate
                result.IssuerInfo = Verifier.Verify(authCert);
            }
            else
            {
                result.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            }

            return result;
             
        }

        public static CertificateSecurityInformation Verify(BC::X509Certificate cert)
        {
            return VerifyInternal(cert, (X509Certificate2Collection)null, DateTime.Now);
        }

        public static CertificateSecurityInformation Verify(BC::X509Certificate cert, DateTime date)
        {
            return VerifyInternal(cert, (X509Certificate2Collection) null, date);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands")]
        internal static CertificateSecurityInformation VerifyInternal(BC::X509Certificate cert, X509Certificate2Collection extraStore, DateTime date)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            AsymmetricKeyParameter key = cert.GetPublicKey();

            //check key type
            if (!(key is RsaKeyParameters) && !(key is DsaKeyParameters)) result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);

            //check key size
            if (!VerifyKeySize(key, EteeActiveConfig.Unseal.MinimuumSignatureKeySize)) result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);

            //check key usage
            if (!cert.GetKeyUsage()[0])
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
            }

            //Check certificate status + validity
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; //todo: make configuratble
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = date;
            if (extraStore != null) chain.ChainPolicy.ExtraStore.AddRange(extraStore);
            chain.Build(new X509Certificate2(cert.GetEncoded()));

            bool partial = false;
            foreach (X509ChainStatus status in chain.ChainStatus)
            {
                switch (status.Status)
                {
                    case X509ChainStatusFlags.NoError:
                        break;
                    case X509ChainStatusFlags.PartialChain:
                        partial = true;
                        break;
                    case X509ChainStatusFlags.CtlNotSignatureValid:
                    case X509ChainStatusFlags.CtlNotTimeValid:
                    case X509ChainStatusFlags.CtlNotValidForUsage:
                        throw new NotSupportedException("This case isn't supported yet, please contact support");
                    default:
                        //Ignore
                        break;
                }
            }

            X509ChainElementEnumerator chainEnum = chain.ChainElements.GetEnumerator();
            if (chainEnum.MoveNext())
            {
                Translate(result, chainEnum, partial);
            }

            return result;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        private static bool VerifyKeySize(AsymmetricKeyParameter key, int minKeySize)
        {
            if (key is RsaKeyParameters)
            {
                if (((RsaKeyParameters)key).Modulus.BitLength < minKeySize)
                {
                    return false;
                }
            }
            else if (key is DsaKeyParameters)
            {
                if (((DsaKeyParameters)key).Parameters.P.BitLength < minKeySize)
                {
                    return false;
                }
            }
            return true;
        }

        public static SecurityInformation Verify(CmsSignedData signedData, CertificateSecurityInformation overrideOrigine)
        {
            return Verify(signedData, overrideOrigine, true);
        }

        public static SecurityInformation Verify(CmsSignedData signedData, CertificateSecurityInformation overrideOrigine, bool strict)
        {
            IX509Store certs = signedData.GetCertificates("COLLECTION");
            IX509Store crls = signedData.GetCrls("COLLECTION");
            SignerInformationStore signerInfos = signedData.GetSignerInfos();

            return Verify(certs, crls, signerInfos, overrideOrigine, strict, false);
        }

        public static SecurityInformation Verify(CmsSignedDataParser signedData, CertificateSecurityInformation overrideOrigine)
        {
            IX509Store certs = signedData.GetCertificates("COLLECTION");
            IX509Store crls = signedData.GetCrls("COLLECTION");
            SignerInformationStore signerInfos = signedData.GetSignerInfos();

            return Verify(certs, crls, signerInfos, overrideOrigine, true, true);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "crls")]
        public static SecurityInformation Verify(IX509Store certs, IX509Store crls, SignerInformationStore signerInfos, CertificateSecurityInformation overrideOrigine, bool strict, bool isStream)
        {
            SignerInformation signerInfo = null;
            BC::X509Certificate signerCert = null;
            SecurityInformation result = new SecurityInformation();

            //Check if signed (only allow single signatures)
            switch (signerInfos.Count)
            {
                case 0:
                    result.securityViolations.Add(SecurityViolation.NotSigned);
                    return result;
                case 1:
                    IEnumerator iterator = signerInfos.GetSigners().GetEnumerator();
                    if (!iterator.MoveNext()) throw new InvalidOperationException("There is one signature, but it could not be retrieved");
                    signerInfo = (SignerInformation)iterator.Current;
                    break;
                default:
                    throw new NotSupportedException("The library doesn't support messages that is signed multiple times");
            }

            if (isStream && signerInfo.SignedAttributes == null)
            {
                throw new NotSupportedException("PSS without signed attributes isn't supported");
            }

            if (strict)
            {
                //check if signer used correct digest algo
                if (signerInfo.DigestAlgOid != EteeActiveConfig.Unseal.SignatureAlgorithm.DigestAlgorithm.Value)
                {
                    result.securityViolations.Add(SecurityViolation.NotAllowedSignatureDigestAlgorithm);
                }

                //check if signer used correct encrypt algo
                if (signerInfo.EncryptionAlgOid != EteeActiveConfig.Unseal.SignatureAlgorithm.EncryptionAlgorithm.Value)
                {
                    result.securityViolations.Add(SecurityViolation.NotAllowedSignatureEncryptionAlgorithm);
                }
            }

            if (overrideOrigine == null)
            {
                //if no signer cert is provided, use the one in the file
                ICollection signerCerts = certs.GetMatches(signerInfo.SignerID);
                switch (signerCerts.Count)
                {
                    case 0:
                        result.securityViolations.Add(SecurityViolation.NotFoundSigner);
                        return result;
                    case 1:
                        IEnumerator iterator = signerCerts.GetEnumerator();
                        if (!iterator.MoveNext()) throw new InvalidOperationException("Signer certificate found, but could not be retrieved");
                        signerCert = (BC::X509Certificate)iterator.Current;
                        if (signerInfo != null && signerInfo.SignedAttributes != null)
                        {
                            Org.BouncyCastle.Asn1.Cms.Attribute time = signerInfo.SignedAttributes[CmsAttributes.SigningTime];
                            if (time != null && time.AttrValues.Count == 1)
                            {
                                result.Subject = Verifier.Verify(signerCert, Time.GetInstance(time.AttrValues[0]).Date);
                            }
                            else
                            {
                                result.Subject = Verifier.Verify(signerCert);
                            }
                        }
                        else
                        {
                            result.Subject = Verifier.Verify(signerCert);
                        }
                        break;
                    default:
                        throw new NotSupportedException("More then one certificate found that corresponds to the sender information in the message, this isn't supported by the library");
                }
            }
            else
            {
                result.Subject = overrideOrigine;
                signerCert = DotNetUtilities.FromX509Certificate(overrideOrigine.Certificate);
            }

            //verify the signature
            if (!signerInfo.Verify(signerCert.GetPublicKey())) result.securityViolations.Add(SecurityViolation.NotSignatureValid);

            return result;
        }
    }
}
