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
using System.Security.Permissions;
using System.Threading;
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
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Egelke.EHealth.Client.Tsa;
using Org.BouncyCastle.Tsp;
using System.Linq;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Receiver;

namespace Egelke.EHealth.Etee.Crypto
{
    internal class TripleUnwrapper : IDataUnsealer, IDataVerifier, ITmaDataVerifier
    {
        private class WinX509CollectionStore : IX509Store
        {
            private X509Certificate2Collection win;
            private IList bc;

            public WinX509CollectionStore(X509Certificate2Collection collection)
            {
                win = collection;
                bc = new List<Org.BouncyCastle.X509.X509Certificate>();
                for (int i = 0; i < collection.Count; i++ )
                {
                    bc.Add(DotNetUtilities.FromX509Certificate(collection[i]));
                }
            }

            public ICollection GetMatches(IX509Selector selector)
            {
                if (selector == null)
                {
                    return win;
                }

                IList result = new ArrayList();
                for (int i = 0; i < win.Count; i++)
                {
                    if (selector.Match(bc[i]))
                        result.Add(win[i]);
                }
                return result;
            }
        }

        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private Level? level;
        private IX509Store encCertStore;
        private ITimemarkProvider timemarkauthority;

        internal TripleUnwrapper(Level? level, ITimemarkProvider timemarkauthority, X509Certificate2Collection encCerts)
        {
            if (level == Level.L_Level || level == Level.A_level ) throw new ArgumentException("level", "Only null or levels B, T, LT and LTA are allowed");

            this.level = level;
            this.timemarkauthority = timemarkauthority;
            //Wrap it inside a IX509Store to (incorrectly) returns an windows x509Certificate2
            encCertStore = encCerts == null || encCerts.Count == 0 ? null : new WinX509CollectionStore(encCerts);
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

        public SignatureSecurityInformation Verify(Stream sealedData)
        {
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
            if (info.SigningTime == null) throw new InvalidMessageException("Verification with timemarking can't be done on Java v1 messages, only on v2 messages and .Net v1 messages");

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
            trace.TraceEvent(TraceEventType.Information, 0, "Unsealing message of {0} bytes for {1} recipient", sealedData.Length, key == null ? "known" : "unknown"); 

            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();
            ITempStreamFactory factory = streaming && sealedData.Length > Settings.Default.InMemorySize ? (ITempStreamFactory) new TempFileStreamFactory() : (ITempStreamFactory) new MemoryStreamFactory();

            Stream verified = factory.CreateNew();
            using(verified)
            {
                result.SecurityInformation.OuterSignature = streaming ?
                    VerifyStreaming(verified, sealedData, null) : 
                    VerifyInMem(verified, sealedData, null);
                trace.TraceEvent(TraceEventType.Information, 0, "Verified the outer signature");

                verified.Position = 0; //reset the stream

                Stream decryptedVerified = factory.CreateNew();
                using (decryptedVerified)
                {
                    result.SecurityInformation.Encryption = Decrypt(decryptedVerified, verified, key, result.SecurityInformation.OuterSignature.SigningTime); //always via stream, it works
                    trace.TraceEvent(TraceEventType.Information, 0, "Decrypted the message");

                    decryptedVerified.Position = 0; //reset the stream

                    result.UnsealedData = factory.CreateNew();
                    result.SecurityInformation.InnerSignature = streaming ?
                        VerifyStreaming(result.UnsealedData, decryptedVerified, result.SecurityInformation.OuterSignature) :
                        VerifyInMem(result.UnsealedData, decryptedVerified, result.SecurityInformation.OuterSignature);
                    trace.TraceEvent(TraceEventType.Information, 0, "Verified the inner signature, finished");

                    result.UnsealedData.Position = 0; //reset the stream

                    return result;
                }
            }
        }

        private SignatureSecurityInformation VerifyStreaming(Stream verifiedContent, Stream signed, SignatureSecurityInformation outer)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the signature");
            try
            {
                CmsSignedDataParser signedData;
                try
                {
                    signedData = new CmsSignedDataParser(signed);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Readed the cms header");
                }
                catch (Exception e)
                {
                    throw new InvalidMessageException("The message isn't a tripple wrapped message", e);
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
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

        private SignatureSecurityInformation VerifyInMem(Stream verifiedContent, Stream signed, SignatureSecurityInformation outer)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying the signature");
            try
            {
                CmsSignedData signedData;
                try
                {
                    signedData = new CmsSignedData(signed);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Readed the cms header");
                }
                catch (Exception e)
                {
                    throw new InvalidMessageException("The message isn't a tripple wrapped message", e);
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
            catch(CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

        private SignatureSecurityInformation Verify(SignerInformationStore signerInfos, IX509Store certs, SignatureSecurityInformation outer)
        {
            SignatureSecurityInformation result = new SignatureSecurityInformation();

            //Check if signed (only allow single signatures)
            SignerInformation signerInfo = null;
            switch (signerInfos.Count)
            {
                case 0:
                    result.securityViolations.Add(SecurityViolation.NotSigned);
                    trace.TraceEvent(TraceEventType.Warning, 0, "Althoug it is a correct CMS file it isn't signed");
                    return result;
                case 1:
                    IEnumerator iterator = signerInfos.GetSigners().GetEnumerator();
                    if (!iterator.MoveNext()) throw new InvalidOperationException("There is one signature, but it could not be retrieved");
                    signerInfo = (SignerInformation)iterator.Current;
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Found signature");
                    break;
                default:
                    trace.TraceEvent(TraceEventType.Error, 0, "Found more then one signature, this isn't supported (yet)");
                    throw new NotSupportedException("The library doesn't support messages that is signed multiple times");
            }

            //check if signer used correct digest algo
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

                //Geting the first certificate
                signerCert = (Org.BouncyCastle.X509.X509Certificate)signerCerts.Current;

                trace.TraceEvent(TraceEventType.Verbose, 0, "Found the signer certificate: {0}", signerCert.SubjectDN.ToString());
                if (signerCerts.MoveNext())
                {
                    //found several certificates...
                    trace.TraceEvent(TraceEventType.Error, 0, "Several certificates correspond to the signer");
                    throw new NotSupportedException("More then one certificate found that corresponds to the sender information in the message, this isn't supported by the library");
                }
            }
            else
            {
                //The subject is the same as the outer
                result.Subject = outer.Subject;
                signerCert = DotNetUtilities.FromX509Certificate(result.Subject.Certificate);
                trace.TraceEvent(TraceEventType.Verbose, 0, "An already validated certificates was provided: {0}", signerCert.SubjectDN.ToString());

                //Additional check, is the authentication certificate also valid for signatures?
                if (!DotNetUtilities.FromX509Certificate(result.Subject.Certificate).GetKeyUsage()[1])
                {
                    result.Subject.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
                }
            }

            //verify the signature itself
            result.SignatureValue = signerInfo.GetSignature();
            if (!signerInfo.Verify(signerCert.GetPublicKey()))
            {
                result.securityViolations.Add(SecurityViolation.NotSignatureValid);
                trace.TraceEvent(TraceEventType.Warning, 0, "The signature value was invalid");
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Signature value verification finished");

            //Get the signing time
            DateTime signingTime = DateTime.UtcNow;
            if (signerInfo != null && signerInfo.SignedAttributes != null)
            {
                Org.BouncyCastle.Asn1.Cms.Attribute time = signerInfo.SignedAttributes[CmsAttributes.SigningTime];
                if (time != null && time.AttrValues.Count > 0)
                {
                    result.SigningTime = Org.BouncyCastle.Asn1.Cms.Time.GetInstance(time.AttrValues[0]).Date;
                    signingTime = result.SigningTime.Value;
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains a signing time: {0}", result.SigningTime);
                }
            }

            //Validating signature info
            if (this.level == null)
            {
                if (outer == null)
                    result.Subject = CertVerifier.VerifyAuth(signerCert, signingTime, certs, null, null, false, false);
                else
                    result.Subject = CertVerifier.VerifySign(signerCert, signingTime, certs, null, null, false, false);
                return result;
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
                    if (revocationValues.GetCrlVals() != null) crls = new List<CertificateList>(revocationValues.GetCrlVals());
                    if (revocationValues.GetOcspVals() != null) ocsps = new List<BasicOcspResponse>(revocationValues.GetOcspVals());
                }
            }

            //check for a timestamp, even if not required
            DateTime validationTime;
            TimeStampToken tst = null;
            bool isSigingTimeValidated;
            if (signerInfo != null && signerInfo.UnsignedAttributes != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains unsigned attributes");
                Org.BouncyCastle.Asn1.Cms.Attribute tstList = signerInfo.UnsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
                if (tstList != null && tstList.AttrValues.Count > 0)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains Signature Time Stamp Token");
                    tst = tstList.AttrValues[0].GetEncoded().ToTimeStampToken();
                }
            }
            if (tst == null)
            {
                //Retrieve the timemark if needed by the level only
                if ((this.level & Level.T_Level) == Level.T_Level)
                {
                    if (outer == null)
                    {
                        //we are in the outer signature, so we need a time-mark (or time-stamp, but we checked that already)
                        if (timemarkauthority == null) throw new InvalidMessageException("The message does not contain a timestamp and there is not timemarkauthority provided while T-Level is required");
                        validationTime = timemarkauthority.GetTimemark(new X509Certificate2(signerCert.GetEncoded()), signingTime, signerInfo.GetSignature());
                    }
                    else
                    {
                        //we are in the inner signature, we check the signing time agains the outer signatures signing time
                        validationTime = outer.SigningTime.Value;
                    }
                }
                else
                {
                    isSigingTimeValidated = false;
                    validationTime = signingTime;
                }
            }
            else
            {
                //Check the timestamp
                Timestamp stamp;
                if ((this.level & Level.A_level) == Level.A_level)
                {
                    //TODO::follow the chain of A-timestamps until the root (now we assume the signature timestamp is the root)
                    stamp = tst.Validate(ref crls, ref ocsps, null);
                } 
                else {
                    stamp = tst.Validate(ref crls, ref ocsps);
                }
                result.TimestampRenewalTime = stamp.RenewalTime;

                //we get the time from the timestamp
                validationTime = stamp.Time;

                if (stamp.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0) {
                    isSigingTimeValidated = false;
                    result.securityViolations.Add(SecurityViolation.InvalidTimestamp);
                }
            }

            //lest check if the signing time is in line with the validation time (obtained from time-mark, outer signature or time-stamp)
            if (validationTime > (signingTime + EteeActiveConfig.ClockSkewness + Settings.Default.TimestampGracePeriod)
                || validationTime < (signingTime - EteeActiveConfig.ClockSkewness))
            {
                isSigingTimeValidated = false;
                result.securityViolations.Add(SecurityViolation.SealingTimeInvalid);
            }
            else
            {
                isSigingTimeValidated = true;
            }

            //If the subject is already provided, so we don't have to do the next check
            if (result.Subject != null) return result;
            
            //check the status on the available info, for unseal it does not matter if it is B-Level or LT-Level.
            if (outer == null)
                result.Subject = CertVerifier.VerifyAuth(signerCert, signingTime, certs, crls, ocsps, true, isSigingTimeValidated);
            else
                result.Subject = CertVerifier.VerifySign(signerCert, signingTime, certs, crls, ocsps, true, isSigingTimeValidated);

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
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Readed the cms header");
                }
                catch (Exception e)
                {
                    trace.TraceEvent(TraceEventType.Error, 0, "The messages isn't encrypted");
                    throw new InvalidMessageException("The message isn't a tripple wrapped message", e);
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
                RecipientInformation recipientInfo;
                ICipherParameters recipientKey;
                if (key == null)
                {
                    if (encCertStore != null)
                    {
                        //Find find a matching receiver
                        ICollection recipients = recipientInfos.GetRecipients(); //recipients in the message
                        IList<KeyValuePair<RecipientInformation, IList>> allMatches = new List<KeyValuePair<RecipientInformation, IList>>();
                        foreach (RecipientInformation recipient in recipients)
                        {
                            if (recipient is KeyTransRecipientInformation) {
                                IList matches = (IList) encCertStore.GetMatches(recipient.RecipientID);
                                if (matches.Count > 0)
                                {
                                    allMatches.Add(new KeyValuePair<RecipientInformation, IList>(recipient, matches));
                                }
                            }
                        }

                        //Did we find a receiver?
                        if (allMatches.Count == 0)
                        {
                            trace.TraceEvent(TraceEventType.Error, 0, "The recipients doe not contain any of your your encryption certificates");
                            throw new InvalidMessageException("The message isn't a message that is addressed to you.  Or it is an unaddressed message or it is addressed to somebody else");
                        }

                        //check with encryption cert matches where valid at creation time
                        IList<KeyValuePair<RecipientInformation, IList>> validMatches = new List<KeyValuePair<RecipientInformation, IList>>();
                        foreach (KeyValuePair<RecipientInformation, IList> match in allMatches)
                        {
                            IList validCertificate = new List<X509Certificate2>();
                            foreach (X509Certificate2 cert in match.Value)
                            {
                                //Validate the decription cert, providing minimal info to force minimal validation.
                                CertificateSecurityInformation certVerRes = CertVerifier.VerifyEnc(DotNetUtilities.FromX509Certificate(cert), null, date, null, false);
                                trace.TraceEvent(TraceEventType.Verbose, 0, "Validated potential decryption certificate ({0}) : {1}", cert.Subject, certVerRes);
                                if (certVerRes.SecurityViolations.Count == 0)
                                {
                                    validCertificate.Add(cert);
                                }
                            }

                            if (validCertificate.Count > 0)
                            {
                                validMatches.Add(new KeyValuePair<RecipientInformation, IList>(match.Key, validCertificate));
                            }
                        }

                        //If we have a valid encCert use that one, otherwise use an invalid one (at least we can read it, but should not use it)
                        X509Certificate2 selectedCert;
                        if (validMatches.Count > 0)
                        {
                            selectedCert = (X509Certificate2)validMatches[0].Value[0];
                            recipientInfo = validMatches[0].Key;
                            trace.TraceEvent(TraceEventType.Information, 0, "Found valid decryption certificate ({0}) that matches one the the recipients", selectedCert.Subject);
                        }
                        else
                        {
                            selectedCert = (X509Certificate2)allMatches[0].Value[0];
                            recipientInfo = allMatches[0].Key;
                            trace.TraceEvent(TraceEventType.Warning, 0, "Found *invalid* decryption certificate ({0}) that matches one the the recipients", selectedCert.Subject);
                        }
                        recipientKey = DotNetUtilities.GetKeyPair(selectedCert.PrivateKey).Private;

                        //we validate the selected certificate again to inform the caller
                        result.Subject = CertVerifier.VerifyEnc(DotNetUtilities.FromX509Certificate(selectedCert),  null, date, null, false);
                    }
                    else
                    {
                        trace.TraceEvent(TraceEventType.Error, 0, "The unsealer does not have an decryption certificate and no symmetric key was provided");
                        throw new InvalidOperationException("There should be an receiver (=yourself) and/or a key provided");
                    }
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
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Found symmertic key in recipients of the cms message");

                    //Get receivers key
                    recipientKey = key.BCKey;

                    //Validate the unaddressed key
                    if ((((KeyParameter)recipientKey).GetKey().Length * 8) < EteeActiveConfig.Unseal.MinimumEncryptionKeySize.SymmetricRecipientKey)
                    {
                        result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionKeySize);
                        trace.TraceEvent(TraceEventType.Warning, 0, "The symmetric key was only {0} bits while it should be at leasst {0}", 
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
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

    }
}
