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

using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509.Store;
using Siemens.EHealth.Etee.Crypto.Configuration;
using Siemens.EHealth.Etee.Crypto.Status;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BC = Org.BouncyCastle.X509;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class CertVerifier
    {
        private static TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

        public static CertificateSecurityInformation VerifyAuth(BC::X509Certificate cert, bool nonRepudiation, IX509Store certs, IX509Store crls, Object ocsps, DateTime? date)
        {
            return Verify(cert, nonRepudiation, certs, crls, ocsps, date);
        }

        public static CertificateSecurityInformation VerifyEnc(BC::X509Certificate encCert, BC::X509Certificate authCert, IX509Store certs, IX509Store crls, Object ocsps, DateTime? date)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            result.Certificate = new X509Certificate2(encCert.GetEncoded());

            //check validity
            try
            {
                encCert.CheckValidity(date == null ? DateTime.UtcNow : date.Value);
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
            int[] keyUsageIndexes = new int[] { 2, 3 }; //(TODO: use active config).
            foreach (int i in keyUsageIndexes)
            {
                if (!encCert.GetKeyUsage()[i])
                {
                    result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
                }
            }

            //check issuer/subject
            if (!encCert.IssuerDN.Equivalent(encCert.SubjectDN, false)) result.securityViolations.Add(CertSecurityViolation.HasNotPermittedNameConstraint);

            //check key size
            if (!VerifyKeySize(encCert.GetPublicKey(), EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey)) result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);

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

                //Validate
                result.IssuerInfo = Verify(authCert, false, certs, crls, ocsps, date);
            }
            else
            {
                //We assume that we have the authCert in case it's of a 3rd person, we don't care if its or own encryption cert (we only care for the validity)
                //result.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            }

            return result;
        }

        private static CertificateSecurityInformation Verify(BC::X509Certificate cert, bool nonRepudiation, IX509Store certs, IX509Store crls, Object ocsps, DateTime? date)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            result.Certificate = new X509Certificate2(cert.GetEncoded());

            //check validity
            try
            {
                cert.CheckValidity(date == null ? DateTime.UtcNow : date.Value);
            }
            catch (CertificateExpiredException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }
            catch (CertificateNotYetValidException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }

            AsymmetricKeyParameter key = cert.GetPublicKey();

            //check key type
            if (!(key is RsaKeyParameters))
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key should be RSA but was {0}", key.GetType());
            }

            //check key size
            if (!VerifyKeySize(key, EteeActiveConfig.Unseal.MinimumSignatureKeySize))
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key was smaller then {0}", EteeActiveConfig.Unseal.MinimumSignatureKeySize);
            }

            //check key usage
            int[] keyUsageIndexes;
            if (nonRepudiation)
            {
                keyUsageIndexes = new int[] { 1 };
            }
            else
            {
                keyUsageIndexes = new int[] { 0 };
            }
            foreach (int i in keyUsageIndexes)
            {
                if (!cert.GetKeyUsage()[i])
                {
                    result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
                }
            }

            //Check certificate status + validity
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; //TODO: make dependant on input of CRLS and ocps
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            if (date.HasValue)
            {
                chain.ChainPolicy.VerificationTime = date.Value;
            }
            if (certs != null)
            {
                ICollection authCertMatch = certs.GetMatches(null);
                foreach(BC::X509Certificate extraCert in authCertMatch)
                {
                    chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(extraCert.GetEncoded()));
                }
            }
            chain.Build(result.Certificate);
            trace.TraceEvent(TraceEventType.Verbose, 0, "Created key chain (includes revocation check)");

            //Check the overall result.
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
                        trace.TraceEvent(TraceEventType.Error, 0, "Unexpected X509ChainStatusFlag: {0}", status.Status);
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

            trace.TraceEvent(TraceEventType.Verbose, 0, "Verified certificate {0} for date {1}", cert.SubjectDN.ToString(), date);
            return result;
        }

        private static bool VerifyKeySize(AsymmetricKeyParameter key, int minKeySize)
        {
            if (key is RsaKeyParameters)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((RsaKeyParameters)key).Modulus.BitLength);
                if (((RsaKeyParameters)key).Modulus.BitLength < minKeySize)
                {
                    return false;
                }
            }
            else if (key is DsaKeyParameters)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((DsaKeyParameters)key).Parameters.P.BitLength);
                if (((DsaKeyParameters)key).Parameters.P.BitLength < minKeySize)
                {
                    return false;
                }
            }
            return true;
        }

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
    }
}
