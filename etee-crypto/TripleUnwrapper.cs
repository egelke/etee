/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Utils;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using Org.BouncyCastle.Asn1.Cms;
using System.Collections.Generic;
using Egelke.EHealth.Etee.Crypto.Status;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Pkcs;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Tsp;
using System.Linq;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Org.BouncyCastle.Utilities.Encoders;

namespace Egelke.EHealth.Etee.Crypto
{
    internal class TripleUnwrapper : IDataUnsealer, IDataVerifier, ITmaDataVerifier
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private Level? level;
        private IX509Store encCertStore;
        private IX509Store authCertStore;
        private ITimemarkProvider timemarkauthority;

        public Dictionary<byte[], AsymmetricAlgorithm> PublicKeys { get; private set; }

        internal TripleUnwrapper(Level? level, ITimemarkProvider timemarkauthority, X509Certificate2Collection encCerts, IX509Store authCertStore)
        {
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("level", "Only null or levels B, T, LT and LTA are allowed");

            this.level = level;
            this.timemarkauthority = timemarkauthority;
            this.encCertStore = encCerts == null || encCerts.Count == 0 ? null : new WinX509CollectionStore(encCerts);
            this.authCertStore = authCertStore;
            this.PublicKeys = new Dictionary<byte[], AsymmetricAlgorithm>();
        }

        #region DataUnsealer Members

        public UnsealResult Unseal(Stream sealedData)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");

            try
            {
                return Unseal(sealedData, null, true);
            }
            catch (NotSupportedException)
            {
                //Start over, non optimize
                sealedData.Position = 0;
                return Unseal(sealedData, null, false);
            }
        }

        #endregion

        #region Anonymous Data Unsealer Members

        public UnsealResult Unseal(Stream sealedData, SecretKey key)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");
            if (key == null) throw new ArgumentNullException("key");

            try
            {
                return Unseal(sealedData, key, true);
            }
            catch (NotSupportedException)
            {
                //Start over, in memory
                sealedData.Position = 0;
                return Unseal(sealedData, key, false);
            }
        }

        #endregion

        #region Data Verifier Members

        //todo update tests to work
        public SignatureSecurityInformation Verify(Stream sealedData)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the sealed message {0} bytes according to the level {1}", sealedData.Length, this.level);

            try
            {
                return VerifyStreaming(new NullStream(), sealedData, null);
            }
            catch (NotSupportedException)
            {
                //Start over, non optimize
                sealedData.Position = 0;
                return VerifyInMem(null, sealedData, null);
            }
        }

        public SignatureSecurityInformation Verify(Stream sealedData, out TimemarkKey timemarkKey)
        {
            SignatureSecurityInformation info = Verify(sealedData);
            if (info.SigningTime == null)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The sealed message did not contain a signing time, which is required with the timemarkKey output parameter");
                throw new InvalidMessageException("Verification with time-marking can't be done on Java v1 messages, only on v2 messages and .Net v1 messages");
            }

            timemarkKey = new TimemarkKey();
            timemarkKey.Signer = info.Signer;
            timemarkKey.SigningTime = info.SigningTime.Value;
            timemarkKey.SignatureValue = info.SignatureValue;

            return info;
        }

        #endregion

        #region Tma Data Verifier Members

        public SignatureSecurityInformation Verify(Stream sealedData, DateTime date)
        {
            ITimemarkProvider provider = this.timemarkauthority;
            try
            {
                trace.TraceEvent(TraceEventType.Information, 0, "Presetting the time-mark to: {0}", date);
                this.timemarkauthority = new FixedTimemarkProvider(date);
                return Verify(sealedData);
            }
            finally
            {
                this.timemarkauthority = provider;
            }
        }

        public SignatureSecurityInformation Verify(Stream sealedData, DateTime date, out TimemarkKey timemarkKey)
        {
            ITimemarkProvider provider = this.timemarkauthority;
            try
            {
                trace.TraceEvent(TraceEventType.Information, 0, "Presetting the time-mark to: {0}", date);
                this.timemarkauthority = new FixedTimemarkProvider(date);
                return Verify(sealedData, out timemarkKey);
            }
            finally
            {
                this.timemarkauthority = provider;
            }
        }

        #endregion

        private UnsealResult Unseal(Stream sealedData, SecretKey key, bool streaming)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Unsealing message of {0} bytes for {1} recipient with level {2}", sealedData.Length, key == null ? "known" : "unknown", this.level);

            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();
            ITempStreamFactory factory = streaming && sealedData.Length > Settings.Default.InMemorySize ? (ITempStreamFactory)new TempFileStreamFactory() : (ITempStreamFactory)new MemoryStreamFactory();

            Stream verified = factory.CreateNew();
            using (verified)
            {
                result.SecurityInformation.OuterSignature = streaming ?
                    VerifyStreaming(verified, sealedData, null) :
                    VerifyInMem(verified, sealedData, null);

                verified.Position = 0; //reset the stream

                Stream decryptedVerified = factory.CreateNew();
                using (decryptedVerified)
                {
                    result.SecurityInformation.Encryption = Decrypt(decryptedVerified, verified, key, result.SecurityInformation.OuterSignature.SigningTime); //always via stream, it works

                    decryptedVerified.Position = 0; //reset the stream

                    result.UnsealedData = factory.CreateNew();
                    result.SecurityInformation.InnerSignature = streaming ?
                        VerifyStreaming(result.UnsealedData, decryptedVerified, result.SecurityInformation.OuterSignature) :
                        VerifyInMem(result.UnsealedData, decryptedVerified, result.SecurityInformation.OuterSignature);

                    result.UnsealedData.Position = 0; //reset the stream

                    return result;
                }
            }
        }

        private SignatureSecurityInformation VerifyStreaming(Stream verifiedContent, Stream signed, SignatureSecurityInformation outer)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the {0} signature streamed", outer == null ? "inner" : "outer");
            try
            {
                CmsSignedDataParser signedData;
                try
                {
                    signedData = new CmsSignedDataParser(signed);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Read the cms header");
                }
                catch (Exception e)
                {
                    trace.TraceEvent(TraceEventType.Error, 0, "The message isn't a CMS Signed Data message: {0}", e.Message);
                    throw new InvalidMessageException("The message isn't a triple wrapped message", e);
                }

                signedData.GetSignedContent().ContentStream.CopyTo(verifiedContent);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Copied the signed data & calculated the message digest");

                IX509Store certs = signedData.GetCertificates("COLLECTION");
                SignerInformationStore signerInfos = signedData.GetSignerInfos();

                return Verify(signerInfos, certs, outer);
            }
            catch (CmsException cmse)
            {
                if (cmse.Message.Contains("RSAandMGF1 not supported"))
                {
                    throw new NotSupportedException("RSA-PSS not supported with streaming in case of raw signatures");
                }
                throw new InvalidMessageException("The message isn't a triple wrapped message", cmse);
            }
        }

        private SignatureSecurityInformation VerifyInMem(Stream verifiedContent, Stream signed, SignatureSecurityInformation outer)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the {0} signature in memory", outer == null ? "inner" : "outer");
            try
            {
                CmsSignedData signedData;
                try
                {
                    signedData = new CmsSignedData(signed);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Read the cms header");
                }
                catch (Exception e)
                {
                    trace.TraceEvent(TraceEventType.Error, 0, "The message isn't a CMS Signed Data message: {0}", e.Message);
                    throw new InvalidMessageException("The message isn't a triple wrapped message", e);
                }

                if (verifiedContent != null)
                {
                    signedData.SignedContent.Write(verifiedContent);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Copied the signed data");
                }

                IX509Store certs = signedData.GetCertificates("COLLECTION");
                SignerInformationStore signerInfos = signedData.GetSignerInfos();
                return Verify(signerInfos, certs, outer);
            }
            catch (CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a triple wrapped message", cmse);
            }
        }

        //todo test is up
        private SignatureSecurityInformation Verify(SignerInformationStore signerInfos, IX509Store certs, SignatureSecurityInformation outer)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the {0} signature information", outer == null ? "outer" : "inner");
            SignatureSecurityInformation result = new SignatureSecurityInformation();

            //Check if signed (only allow single signatures)
            SignerInformation signerInfo = null;
            IEnumerator iterator = signerInfos.GetSigners().GetEnumerator();
            if (!iterator.MoveNext()) {
                result.securityViolations.Add(SecurityViolation.NotSigned);
                trace.TraceEvent(TraceEventType.Warning, 0, "Although it is a correct CMS file it isn't signed");
                return result;
            }

            signerInfo = (SignerInformation)iterator.Current;

            trace.TraceEvent(TraceEventType.Verbose, 0, "Found signature, with signer ID = issuer {0} and serial number {1}", signerInfo.SignerID.Issuer, signerInfo.SignerID.SerialNumber);
            if (iterator.MoveNext())
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Found more then one signature, this isn't supported (yet)");
                throw new InvalidMessageException("An eHealth compliant message can have only one signer");
            }


            //check if signer used correct digest algorithm
            int i = 0;
            bool found = false;
            StringBuilder algos = new StringBuilder();
            while (!found && i < EteeActiveConfig.Unseal.SignatureAlgorithms.Count)
            {
                Oid algoDigest = EteeActiveConfig.Unseal.SignatureAlgorithms[i].DigestAlgorithm;
                Oid algoEnc = EteeActiveConfig.Unseal.SignatureAlgorithms[i++].EncryptionAlgorithm;
                algos.Append(algoDigest.Value + " (" + algoDigest.FriendlyName + ") + " + algoEnc.Value + " (" + algoEnc.FriendlyName + "), ");
                found = (algoDigest.Value == signerInfo.DigestAlgOid) && (algoEnc.Value == signerInfo.EncryptionAlgOid);
            }
            if (!found)
            {
                result.securityViolations.Add(SecurityViolation.NotAllowedSignatureDigestAlgorithm);
                trace.TraceEvent(TraceEventType.Warning, 0, "The signature digest + encryption algorithm {0} + {1} isn't allowed, only {2} are",
                    signerInfo.DigestAlgOid, signerInfo.EncryptionAlgOid, algos);
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Verified the signature digest and encryption algorithm");

            //Find the singing certificate and relevant info
            Org.BouncyCastle.X509.X509Certificate signerCert = null;
            byte[] ski = null;
            if (certs.GetMatches(null).Count > 0)
            {
                //We got certificates, so lets find the signer
                IEnumerator signerCerts = certs.GetMatches(signerInfo.SignerID).GetEnumerator();

                if (!signerCerts.MoveNext())
                {
                    //found no certificate
                    result.securityViolations.Add(SecurityViolation.NotFoundSigner);
                    trace.TraceEvent(TraceEventType.Warning, 0, "Could not find the signer certificate");
                    return result;
                }

                //Getting the first certificate
                signerCert = (Org.BouncyCastle.X509.X509Certificate)signerCerts.Current;
                trace.TraceEvent(TraceEventType.Verbose, 0, "Found the signer certificate: {0}", signerCert.SubjectDN.ToString());

                //Check if the outer certificate matches the inner certificate
                if (outer != null)
                {
                    Org.BouncyCastle.X509.X509Certificate authCert = DotNetUtilities.FromX509Certificate(outer.Subject.Certificate);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Comparing The signer certificate {0} ({1}) with the authentication certificate {2} ({3})",
                            signerCert.SubjectDN, signerCert.IssuerDN, authCert.SubjectDN, authCert.IssuerDN);
                    //_safe_ check if the serial numbers of the subject name are equal and they have the same issuer
                    if (!authCert.SubjectDN.GetOidList().Contains(X509Name.SerialNumber)
                        || !signerCert.SubjectDN.GetOidList().Contains(X509Name.SerialNumber)
                        || authCert.SubjectDN.GetValueList(X509Name.SerialNumber).Count != 1
                        || signerCert.SubjectDN.GetValueList(X509Name.SerialNumber).Count != 1
                        || !authCert.SubjectDN.GetValueList(X509Name.SerialNumber)[0].Equals(signerCert.SubjectDN.GetValueList(X509Name.SerialNumber)[0])
                        || !authCert.IssuerDN.Equals(signerCert.IssuerDN))
                    {
                        result.securityViolations.Add(SecurityViolation.SubjectDoesNotMachEnvelopingSubject);
                        trace.TraceEvent(TraceEventType.Warning, 0, "The signer certificate {0} ({1}) does not match the authentication certificate {2} ({3})",
                            signerCert.SubjectDN, signerCert.IssuerDN, authCert.SubjectDN, authCert.IssuerDN);
                    }
                }

                if (signerCerts.MoveNext())
                {
                    //found several certificates...
                    trace.TraceEvent(TraceEventType.Error, 0, "Several certificates correspond to the signer");
                    throw new NotSupportedException("More then one certificate found that corresponds to the sender information in the message, this isn't supported by the library");
                }
            }
            else
            {
                //todo here is failed
                if (outer == null)
                {
                    //we do not need certificate
                    ski = signerInfo.SignerID.SubjectKeyIdentifier;

                    //we do not have certificate and ski
                    if (ski == null)
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "The outer signature does not contain any certificates");
                        throw new InvalidMessageException("The outer signature is missing certificates");
                    }
                    else 
                    {
                        result.SignerId = ski;
                    }

                }
                else
                {
                    //The subject is the same as the outer
                    result.Subject = outer.Subject;
                    signerCert = DotNetUtilities.FromX509Certificate(outer.Subject.Certificate);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "An already validated certificates was provided: {0}", signerCert.SubjectDN.ToString());
                }

            }

            //check if non repudiation
            result.IsNonRepudiatable = signerCert == null ? false : signerCert.GetKeyUsage()[1];

            //verify the signature itself
            result.SignatureValue = signerInfo.GetSignature();
            //TODO check
            if ((signerCert != null && !signerInfo.Verify(signerCert.GetPublicKey()))||
                (ski != null && PublicKeys.Any() && !signerInfo.Verify(PublicKeys[ski].ToAsymmetricKeyParameter())))
            {
                result.securityViolations.Add(SecurityViolation.NotSignatureValid);
                trace.TraceEvent(TraceEventType.Warning, 0, "The signature value was invalid");
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Signature value verification finished");

            //Get the signing time
            bool hasSigningTime = false;
            DateTime signingTime = DateTime.UtcNow;
            if (signerInfo != null && signerInfo.SignedAttributes != null)
            {
                Org.BouncyCastle.Asn1.Cms.Attribute time = signerInfo.SignedAttributes[CmsAttributes.SigningTime];
                if (time != null && time.AttrValues.Count > 0)
                {
                    hasSigningTime = true;
                    result.SigningTime = Org.BouncyCastle.Asn1.Cms.Time.GetInstance(time.AttrValues[0]).Date;
                    signingTime = result.SigningTime.Value;
                    if (signingTime.Kind == DateTimeKind.Unspecified)
                    {
                        signingTime = new DateTime(signingTime.Ticks, DateTimeKind.Utc);
                    }
                    else
                    {
                        signingTime = signingTime.ToUniversalTime();
                    }
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains a signing time: {0}", result.SigningTime);
                }
            }

            //Get the embedded CRLs and OCSPs
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            if (signerInfo != null && signerInfo.UnsignedAttributes != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains unsigned attributes");
                Org.BouncyCastle.Asn1.Cms.Attribute revocationValuesList = signerInfo.UnsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues];
                if (revocationValuesList != null && revocationValuesList.AttrValues.Count > 0)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains Revocation Values");
                    RevocationValues revocationValues = RevocationValues.GetInstance(revocationValuesList.AttrValues[0]);
                    if (revocationValues.GetCrlVals() != null)
                    {
                        crls = new List<CertificateList>(revocationValues.GetCrlVals());
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Found {0} CRL's in the message", crls.Count);
                    }
                    if (revocationValues.GetOcspVals() != null)
                    {
                        ocsps = new List<BasicOcspResponse>(revocationValues.GetOcspVals());
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Found {0} OCSP's in the message", ocsps.Count);
                    }
                }
            }

            //check for a time-stamp, if needed and we are in the outer layer
            if ((this.level & Level.T_Level) == Level.T_Level && outer == null)
            {
                if (signerCert == null)
                {
                    throw new InvalidMessageException("WebAuth does not support Timestapms");
                }

                DateTime validatedTime;
                TimeStampToken tst = null;
                if (signerInfo != null && signerInfo.UnsignedAttributes != null)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains unsigned attributes");
                    Org.BouncyCastle.Asn1.Cms.Attribute tstList = signerInfo.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
                    if (tstList != null && tstList.AttrValues.Count > 0)
                    {
                        trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains the Signature Time Stamp Token: {0}", Convert.ToBase64String(tstList.AttrValues[0].GetEncoded()));
                        tst = tstList.AttrValues[0].GetEncoded().ToTimeStampToken();
                    }
                }

                if (tst == null)
                {
                    //we are in the outer signature, so we need a time-mark (or time-stamp, but we checked that already)
                    if (timemarkauthority == null)
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "Not time-mark authority is provided while there is not embedded time-stamp, the level includes T-Level and it isn't an inner signature");
                        throw new InvalidMessageException("The message does not contain a time-stamp and there is not time-mark authority provided while T-Level is required");
                    }
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Requesting time-mark for message signed by {0}, signed on {1} and with signature value {2}",
                       signerCert.SubjectDN, signingTime, signerInfo.GetSignature());
                    validatedTime = timemarkauthority.GetTimemark(new X509Certificate2(signerCert.GetEncoded()), signingTime, signerInfo.GetSignature()).ToUniversalTime();
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The validated time is the return time-mark which is: {0}", validatedTime);
                }
                else
                {
                    //Check the time-stamp
                    if (!tst.IsMatch(new MemoryStream(signerInfo.GetSignature())))
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "The time-stamp does not match the message");
                        result.securityViolations.Add(SecurityViolation.InvalidTimestamp);
                    }

                    Timestamp stamp;
                    if ((this.level & Level.A_level) == Level.A_level)
                    {
                        //TODO::follow the chain of A-timestamps until the root (now we assume the signature time-stamp is the root)
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Validating the time-stamp against the current time for arbitration reasons");
                        stamp = tst.Validate(crls, ocsps, DateTime.UtcNow);
                    }
                    else {
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Validating the time-stamp against the time-stamp time since no arbitration is needed");
                        stamp = tst.Validate(crls, ocsps);
                    }
                    result.TimestampRenewalTime = stamp.RenewalTime;
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The time-stamp must be renewed on {0}", result.TimestampRenewalTime);

                    //we get the time from the time-stamp
                    validatedTime = stamp.Time;
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The validated time is the time-stamp time which is on {0}", validatedTime);
                    if (!hasSigningTime)
                    {
                        trace.TraceEvent(TraceEventType.Information, 0, "Implicit signing time {0} is replaced with time-stamp time {1}", signingTime, tst.TimeStampInfo.GenTime);
                        signingTime = stamp.Time;
                    }

                    if (stamp.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "The time-stamp is invalid with {0} errors, including {1}: {2}",
                            stamp.TimestampStatus.Count, stamp.TimestampStatus[0].Status, stamp.TimestampStatus[0].StatusInformation);
                        result.securityViolations.Add(SecurityViolation.InvalidTimestamp);
                    }
                }

                //lest check if the signing time is in line with the validation time (obtained from time-mark, outer signature or time-stamp)
                if (validatedTime > (signingTime + EteeActiveConfig.ClockSkewness + Settings.Default.TimestampGracePeriod)
                    || validatedTime < (signingTime - EteeActiveConfig.ClockSkewness))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "The validated time {0} is not in line with the signing time {1} with a grace period of {2}",
                        validatedTime, signingTime, Settings.Default.TimestampGracePeriod);
                    result.securityViolations.Add(SecurityViolation.SealingTimeInvalid);
                }
                else
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The validated time {0} is in line with the signing time {1}", validatedTime, signingTime);
                }
            }

            //calculate the subject status is unknown
            if (result.Subject == null && signerCert != null) {
                result.Subject = signerCert.Verify(signingTime, (outer == null ? new int[] { 0 } : new int[0]),
                    EteeActiveConfig.Unseal.MinimumSignatureKeySize, certs, ref crls, ref ocsps);
                var signer = result.Subject.Certificate.Extensions.ToList().Where(_ => _ != null).Select(_ => Hex.Decode(_.SubjectKeyIdentifier)).FirstOrDefault();
                //TODO check!!! convert to .net version .nethelper
                result.SignerId = signer == null ? Convert.FromBase64String(signerCert.GetPublicKey().ToString()) : signer;

            }

            return result;
        }

      
        private SecurityInformation Decrypt(Stream clear, Stream cypher, SecretKey key, DateTime? sealedOn)
        {
            int i;
            bool found;
            StringBuilder algos;
            DateTime date = sealedOn == null ? DateTime.UtcNow : sealedOn.Value;

            trace.TraceEvent(TraceEventType.Information, 0, "Decrypting message for {0} recipient", key == null ? "known" : "unknown");
            try
            {
                SecurityInformation result = new SecurityInformation();
                CmsEnvelopedDataParser cypherData;
                try
                {
                    cypherData = new CmsEnvelopedDataParser(cypher);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Read the cms header");
                }
                catch (Exception e)
                {
                    trace.TraceEvent(TraceEventType.Error, 0, "The messages isn't encrypted");
                    throw new InvalidMessageException("The message isn't a triple wrapped message", e);
                }
                RecipientInformationStore recipientInfos = cypherData.GetRecipientInfos();
                trace.TraceEvent(TraceEventType.Verbose, 0, "Got the recipient info of the encrypted message");
                
                i = 0;
                found = false;
                algos = new StringBuilder();
                string encryptionAlgOid = cypherData.EncryptionAlgOid;
                while (!found && i < EteeActiveConfig.Unseal.EncryptionAlgorithms.Count)
                {
                    Oid algo = EteeActiveConfig.Unseal.EncryptionAlgorithms[i++];
                    algos.Append(algo.Value + " (" + algo.FriendlyName + ") ");
                    found = algo.Value == encryptionAlgOid;
                }
                if (!found)
                {
                    result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionAlgorithm);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The encryption algorithm {0} isn't allowed, only {1} are", encryptionAlgOid, algos);
                }
                trace.TraceEvent(TraceEventType.Verbose, 0, "The encryption algorithm is verified: {0}", encryptionAlgOid);

                //Key size of the message should not be checked, size is determined by the algorithm

                //Get recipient, should be receiver.
                ICipherParameters recipientKey = null;
                RecipientInformation recipientInfo = null;
                if (key == null)
                {
                    if (encCertStore == null || !PublicKeys.Any())
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "The unsealer does not have an decryption certificate and no symmetric key was provided");
                        throw new InvalidOperationException("There should be an receiver (=yourself) and/or a key provided");
                    }

                    //Find find a matching receiver
                    result.Subject = new CertificateSecurityInformation();
                    foreach (RecipientInformation recipient in recipientInfos.GetRecipients())
                    {
                        trace.TraceEvent(TraceEventType.Verbose, 0, "The message is addressed to {0} ({1})", recipient.RecipientID.SerialNumber, recipient.RecipientID.Issuer);
                        if (recipient is KeyTransRecipientInformation) {
                            //do I have sertificate
                            IList matches = (IList) encCertStore.GetMatches(recipient.RecipientID);
                            foreach (X509Certificate2 match in matches)
                            {
                                trace.TraceEvent(TraceEventType.Verbose, 0, "Found potential match {0} ({1})", match.Subject, match.Issuer);
                                if (match.IsBetter(result.Subject.Certificate, date))
                                {
                                    recipientInfo = recipient;
                                    recipientKey = DotNetUtilities.GetKeyPair(((X509Certificate2)matches[0]).PrivateKey).Private;
                                    result.Subject.Certificate = match;
                                }
                            }

                            //TODO check
                            var pubKey = PublicKeys[recipient.RecipientID.SubjectKeyIdentifier];
                            result.PublicKey = PublicKeys[recipient.RecipientID.SubjectKeyIdentifier];
                        }
                    }

                    //Did we find a receiver?
                    if (recipientKey == null)
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "The recipients doe not contain any of your encryption certificates");
                        throw new InvalidMessageException("The message isn't a message that is addressed to you.  Or it is an unaddressed message or it is addressed to somebody else");
                    }

                    IList<CertificateList> crls = null;
                    IList<BasicOcspResponse> ocsps = null;
                    result.Subject = DotNetUtilities.FromX509Certificate(result.Subject.Certificate).Verify(date, new int[] { 2, 3 }, EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey, authCertStore, ref crls, ref ocsps);
                }
                else
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Found symmetric key: {0}", key.IdString);

                    RecipientID recipientId = new RecipientID();
                    recipientId.KeyIdentifier = key.Id;
                    recipientInfo = recipientInfos.GetFirstRecipient(recipientId);
                    if (recipientInfo == null)
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "The symmetric key was not found in this cms message");
                        throw new InvalidMessageException("The key isn't for this unaddressed message");
                    }
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Found symmetric key in recipients of the cms message");

                    //Get receivers key
                    recipientKey = key.BCKey;

                    //Validate the unaddressed key
                    if ((((KeyParameter)recipientKey).GetKey().Length * 8) < EteeActiveConfig.Unseal.MinimumEncryptionKeySize.SymmetricRecipientKey)
                    {
                        result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionKeySize);
                        trace.TraceEvent(TraceEventType.Warning, 0, "The symmetric key was only {0} bits while it should be at least {0}", 
                            ((KeyParameter)recipientKey).GetKey().Length * 8,  EteeActiveConfig.Unseal.MinimumEncryptionKeySize.SymmetricRecipientKey);
                    }
                }

                //check if key encryption algorithm is allowed
                i = 0;
                found = false;
                algos = new StringBuilder();
                while (!found && i < EteeActiveConfig.Unseal.KeyEncryptionAlgorithms.Count)
                {
                    Oid algo = EteeActiveConfig.Unseal.KeyEncryptionAlgorithms[i++];
                    algos.Append(algo.Value + " (" + algo.FriendlyName + ") ");
                    found = algo.Value == recipientInfo.KeyEncryptionAlgOid;
                }
                if (!found)
                {
                    result.securityViolations.Add(SecurityViolation.NotAllowedKeyEncryptionAlgorithm);
                    trace.TraceEvent(TraceEventType.Warning, 0, "Encryption algorithm is {0} while it should be one of the following {1}",
                        recipientInfo.KeyEncryptionAlgOid, algos);
                }
                trace.TraceEvent(TraceEventType.Verbose, 0, "Finished verifying the encryption algorithm: {0}", recipientInfo.KeyEncryptionAlgOid);

                //Decrypt!
                CmsTypedStream clearStream = recipientInfo.GetContentStream(recipientKey);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Accessed the encrypted content");

                try
                {
                    clearStream.ContentStream.CopyTo(clear);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Decrypted the content");
                }
                finally
                {
                    clearStream.ContentStream.Close();
                }

                return result;
            }
            catch (CmsException cmse)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The message isn't a CMS message");
                throw new InvalidMessageException("The message isn't a triple wrapped message", cmse);
            }
        }

    }
}
