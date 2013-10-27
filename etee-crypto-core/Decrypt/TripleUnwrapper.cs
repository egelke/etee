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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Siemens.EHealth.Etee.Crypto.Configuration;
using Siemens.EHealth.Etee.Crypto.Utils;
using BC = Org.BouncyCastle.X509;
using System.Security.Permissions;
using System.Threading;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using Org.BouncyCastle.Asn1.Cms;
using Egelke.EHealth.Etee.Crypto.Utils;
using System.Collections.Generic;
using Siemens.EHealth.Etee.Crypto.Status;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;

namespace Siemens.EHealth.Etee.Crypto.Decrypt
{
    internal class TripleUnwrapper : IDataUnsealer
    {
        private class WinX509CollectionStore : IX509Store
        {
            private X509Certificate2Collection win;
            private IList bc;

            public WinX509CollectionStore(X509Certificate2Collection collection)
            {
                win = collection;
                bc = new List<BC::X509Certificate>();
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

        private TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

        private IX509Store encCertStore;
        private bool requireProbativeForce;

        internal TripleUnwrapper(bool requireProbativeForce, X509Certificate2Collection encCerts)
        {
            this.requireProbativeForce = requireProbativeForce;

            ///Wrap it inside a IX509Store to (incorrectly) returns an windows x509Certificate2
            encCertStore = encCerts == null || encCerts.Count == 0 ? null : new WinX509CollectionStore(encCerts);
        }

        #region DataUnsealer Members

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
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

        public UnsealResult Unseal(byte[] sealedData)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");

            //No need to optimize for small files that fit in the memory
            MemoryStream tmp = new MemoryStream(sealedData);
            using (tmp)
            {
                return Unseal(tmp, null, false);
            }
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
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

        public UnsealResult Unseal(byte[] sealedData, SecretKey key)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");
            if (key == null) throw new ArgumentNullException("key");

            MemoryStream tmp = new MemoryStream(sealedData);
            using (tmp)
            {
                return Unseal(tmp, key);
            }
            
        }

        #endregion

        private UnsealResult Unseal(Stream sealedData, SecretKey key, bool streaming)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Unsealing message of {0} bytes for {1} recipient", sealedData.Length, key == null ? "known" : "unknown"); 

            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();
            ITempStreamFactory factory = streaming ? (ITempStreamFactory) new TempFileStreamFactory() : (ITempStreamFactory) new MemoryStreamFactory();

            Stream verified = factory.CreateNew();
            using(verified)
            {
                DateTime? date = null;
                result.SecurityInformation.OuterSignature = streaming ?
                    VerifyStreaming(verified, sealedData, null, ref date) : 
                    VerifyInMem(verified, sealedData, null, ref date);
                CertificateSecurityInformation origine = result.SecurityInformation.OuterSignature.Subject;
                trace.TraceEvent(TraceEventType.Information, 0, "Verified the outer signature");

                verified.Position = 0; //reset the stream

                Stream decryptedVerified = factory.CreateNew();
                using (decryptedVerified)
                {
                    result.SecurityInformation.Encryption = Decrypt(decryptedVerified, verified, key, date.Value); //always via stream, it works
                    trace.TraceEvent(TraceEventType.Information, 0, "Decrypted the message");

                    decryptedVerified.Position = 0; //reset the stream

                    result.UnsealedData = factory.CreateNew();
                    result.SecurityInformation.InnerSignature = streaming ?
                        VerifyStreaming(result.UnsealedData, decryptedVerified, origine, ref date) : 
                        VerifyInMem(result.UnsealedData, decryptedVerified, origine, ref date);
                    trace.TraceEvent(TraceEventType.Information, 0, "Verified the inner signature, finished");

                    result.UnsealedData.Position = 0; //reset the stream
                    result.SecurityInformation.SealedOn = date;

                    return result;
                }
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "wait")]
        private SecurityInformation VerifyStreaming(Stream verifiedContent, Stream signed, CertificateSecurityInformation origine, ref DateTime? date)
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

                return Verify(signerInfos, certs, origine, ref date);
            }
            catch (CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "wait")]
        private SecurityInformation VerifyInMem(Stream verifiedContent, Stream signed, CertificateSecurityInformation origine, ref DateTime? date)
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
                signedData.SignedContent.Write(verifiedContent);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Copied the signed data");

                IX509Store certs = signedData.GetCertificates("COLLECTION");
                SignerInformationStore signerInfos = signedData.GetSignerInfos();
                return Verify(signerInfos, certs, origine, ref date);
            }
            catch(CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

        private SecurityInformation Verify(SignerInformationStore signerInfos, IX509Store certs, CertificateSecurityInformation origine, ref DateTime? date)
        {
            SecurityInformation result = new SecurityInformation();

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

            BC::X509Certificate signerCert = null;
            if (origine != null)
            {
                result.Subject = origine;
                signerCert = DotNetUtilities.FromX509Certificate(origine.Certificate);
                trace.TraceEvent(TraceEventType.Verbose, 0, "An already validated certificates was provided: {0}", signerCert.SubjectDN.ToString());
            }
            else
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "No override certificate is provided, finding it in the CMS message.");

                //Find the singing certificate and relevant info
                ICollection signerCerts = certs.GetMatches(signerInfo.SignerID);
                switch (signerCerts.Count)
                {
                    case 0:
                        //No certificate found
                        result.securityViolations.Add(SecurityViolation.NotFoundSigner);
                        trace.TraceEvent(TraceEventType.Warning, 0, "Could not find the signer certificate");
                        return result;
                    case 1:
                        //found single certificate, extracting it.
                        IEnumerator iterator = signerCerts.GetEnumerator();
                        if (!iterator.MoveNext())
                        {
                            trace.TraceEvent(TraceEventType.Error, 0, "Found the signer certificate, but the enumeration was emtpy");
                            throw new InvalidOperationException("Signer certificate found, but could not be retrieved");
                        }
                        signerCert = (BC::X509Certificate)iterator.Current;

                        //get the signing time if present, otherwise set on now
                        date = DateTime.UtcNow;
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Found the signer certificate: {0}", signerCert.SubjectDN.ToString());
                        if (signerInfo != null && signerInfo.SignedAttributes != null)
                        {
                            trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains signed attributes");
                            Org.BouncyCastle.Asn1.Cms.Attribute time = signerInfo.SignedAttributes[CmsAttributes.SigningTime];
                            if (time != null && time.AttrValues.Count > 0)
                            {
                                date = Org.BouncyCastle.Asn1.Cms.Time.GetInstance(time.AttrValues[0]).Date;
                                trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains a signing time: {0}", date);
                            }
                        }

                        //Get the CRLs and OCSPs
                        CertificateList[] rawCrls = new CertificateList[0];
                        BasicOcspResponse[] rawOcsps = new BasicOcspResponse[0];
                        if (signerInfo != null && signerInfo.UnsignedAttributes != null)
                        {
                            trace.TraceEvent(TraceEventType.Verbose, 0, "The CMS message contains unsigned attributes");
                            Org.BouncyCastle.Asn1.Cms.Attribute revocationValuesList = signerInfo.UnsignedAttributes[EsfAttributes.RevocationValues];
                            if (revocationValuesList != null && revocationValuesList.AttrValues.Count > 0)
                            {
                                RevocationValues revocationValues = RevocationValues.GetInstance(revocationValuesList.AttrValues[0]);
                                if (revocationValues.GetCrlVals() != null) rawCrls = revocationValues.GetCrlVals();
                                if (revocationValues.GetOcspVals() != null) rawOcsps = revocationValues.GetOcspVals();
                            }
                        }

                        //convert the CRLs in something useful
                        IList<X509Crl> crls = new List<X509Crl>();
                        foreach (CertificateList rawCrl in rawCrls)
                        {
                            crls.Add(new X509Crl(rawCrl));
                        }

                        //conver the OCSPs in something useful
                        IList<BasicOcspResp> ocsps = new List<BasicOcspResp>();
                        foreach (BasicOcspResponse rawOcsp in rawOcsps)
                        {
                            ocsps.Add(new BasicOcspResp(rawOcsp));
                        }

                        //Validating everything
                        result.Subject = CertVerifier.VerifyAuth(signerCert, requireProbativeForce, certs, crls, ocsps, date.Value);
                        break;
                    default:
                        //found several certificates...
                        trace.TraceEvent(TraceEventType.Error, 0, "Several certificates correspond to the signer");
                        throw new NotSupportedException("More then one certificate found that corresponds to the sender information in the message, this isn't supported by the library");
                }
            }
            
            //verify the signature
            if (!signerInfo.Verify(signerCert.GetPublicKey()))
            {
                result.securityViolations.Add(SecurityViolation.NotSignatureValid);
                trace.TraceEvent(TraceEventType.Warning, 0, "The signature value was invalid");
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Signature value verification finished");

            trace.TraceEvent(TraceEventType.Verbose, 0, "Signature block verified");

            return result;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
        private SecurityInformation Decrypt(Stream clear, Stream cypher, SecretKey key, DateTime date)
        {
            int i;
            bool found;
            StringBuilder algos;

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

                //EXTEND: check key size of message (TODO)

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
                            IList matches = (IList) encCertStore.GetMatches(recipient.RecipientID);
                            if (matches.Count > 0)
                            {
                                allMatches.Add(new KeyValuePair<RecipientInformation, IList>(recipient, matches));
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
                                CertificateSecurityInformation certVerRes = CertVerifier.VerifyEnc(DotNetUtilities.FromX509Certificate(cert), null, null, null, null, date);
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
                        result.Subject = CertVerifier.VerifyEnc(DotNetUtilities.FromX509Certificate(selectedCert), null, null, null, null, date);
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

                clearStream.ContentStream.CopyTo(clear);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Decrypted the content");

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
