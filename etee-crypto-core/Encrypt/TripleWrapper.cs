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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Store;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Utils;
using BC = Org.BouncyCastle;
using System.Security.Permissions;
using System;
using System.Threading;
using System.Diagnostics;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using System.Net;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Egelke.EHealth.Etee.Crypto.Utils;
using Org.BouncyCastle.Asn1.Cms;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Encrypt
{
    internal class TripleWrapper : IDataSealer
    {

        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        //The sender certificate
        private X509Certificate2 sender;

        //The bag of sender certifcate path (in undefined order)
        private IX509Store senderChainStore;

        //The ordered list of sender certificate path (in assending order)
        private IList<X509Certificate2> senderChainList;
        

        internal TripleWrapper(X509Certificate2 sender)
            : this(sender, null)
        {

        }

        internal TripleWrapper(X509Certificate2 sender, X509Certificate2Collection extraStore)
        {
            this.sender = sender;

            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            if (extraStore != null) chain.ChainPolicy.ExtraStore.AddRange(extraStore);
            chain.Build(sender);

            senderChainList = new List<X509Certificate2>();
            X509ChainElementEnumerator chainEnum = chain.ChainElements.GetEnumerator();
            List<BC::X509.X509Certificate> senderChainCollection = new List<BC::X509.X509Certificate>();
            while (chainEnum.MoveNext())
            {
                senderChainList.Add(chainEnum.Current.Certificate);
                senderChainCollection.Add(DotNetUtilities.FromX509Certificate(chainEnum.Current.Certificate));
            }
            senderChainStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(senderChainCollection));
        }

        #region DataSealer Members

        public byte[] Seal(EncryptionToken token, byte[] unsealed)
        {
            List<EncryptionToken> tokens = new List<EncryptionToken>();
            tokens.Add(token);

            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)Seal(factory, unsealedStream, tokens, null);
                using (sealedStream)
                {
                    return sealedStream.ToArray();
                }
            }
        }

        public byte[] Seal(ReadOnlyCollection<EncryptionToken> tokens, byte[] unsealed)
        {
            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)Seal(factory, unsealedStream, tokens, null);
                using (sealedStream)
                {
                    return sealedStream.ToArray();
                }
            }
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public Stream Seal(EncryptionToken token, Stream unsealed)
        {
            List<EncryptionToken> tokens = new List<EncryptionToken>();
            tokens.Add(token);

            ITempStreamFactory factory = new TempFileStreamFactory();
            return Seal(factory, unsealed, tokens, null);
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public Stream Seal(ReadOnlyCollection<EncryptionToken> tokens, Stream unsealed)
        {
            ITempStreamFactory factory = new TempFileStreamFactory();
            return Seal(factory, unsealed, tokens, null);
        }

        public byte[] Seal(byte[] unsealed, SecretKey key)
        {
            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)Seal(factory, unsealedStream, null, key);
                using (sealedStream)
                {
                    return sealedStream.ToArray();
                }
            }
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public Stream Seal(Stream unsealed, SecretKey key)
        {
            List<EncryptionToken> tokens = new List<EncryptionToken>();
            ITempStreamFactory factory = new TempFileStreamFactory();
            return Seal(factory, unsealed, tokens, key);
        }

        public byte[] Seal(ReadOnlyCollection<EncryptionToken> tokens, byte[] unsealed, SecretKey key)
        {
            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)Seal(factory, unsealedStream, tokens, key);
                using (sealedStream)
                {
                    return sealedStream.ToArray();
                }
            }
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public Stream Seal(ReadOnlyCollection<EncryptionToken> tokens, Stream unsealed, SecretKey key)
        {
            ITempStreamFactory factory = new TempFileStreamFactory();
            return Seal(factory, unsealed, tokens, key);
        }

        #endregion

        private Stream Seal(ITempStreamFactory factory, Stream unsealedStream, ICollection<EncryptionToken> tokens, SecretKey key)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Sealing message of {0} bytes for {1} known recipients and {1} unknown recipients", 
                unsealedStream.Length, tokens == null ? 0 : tokens.Count, key == null ? 0 : 1);
            //Create inner signed stream
            Stream signed = factory.CreateNew();
            using (signed)
            {
                //Inner sign
                Sign(signed, unsealedStream, false);

                signed.Position = 0;

                //Create  encrypted stream
                Stream signedEncrypted = factory.CreateNew();
                using (signedEncrypted)
                {
                    //Encrypt
                    Encrypt(signedEncrypted, signed, tokens, key);

                    //Outer sign with retry for eID
                    int tries = 0;
                    Stream sealedStream = null;
                    while (true)
                    {
                        signedEncrypted.Position = 0;

                        try
                        {
                            //This is the output, so we need to make it a temp stream (temp file or memory stream)
                            sealedStream = factory.CreateNew();
                            Sign(sealedStream, signedEncrypted, true);
                            break;
                        }
                        catch (CryptographicException ce)
                        {
                            trace.TraceEvent(TraceEventType.Warning, 0, "Failed to put outer signature (try {0}): {1}", tries, ce);
                            if (tries++ < 4)
                            {
                                sealedStream.Close();
                                sealedStream = null;
                                Thread.Sleep((int) Math.Pow(10, tries)); //wait longer and longer
                            }
                            else
                            {
                                throw ce; 
                            }
                        }
                    }

                    sealedStream.Position = 0; //reset the stream

                    return sealedStream;
                }
            }
        }

        protected void Sign(Stream signed, Stream unsigned, bool includeSigner)
        {
            BC::X509.X509Certificate bcSender = DotNetUtilities.FromX509Certificate(sender);
            trace.TraceEvent(TraceEventType.Information, 0, "Signing the message in name of {0}", bcSender.SubjectDN.ToString());

            //Signing time
            DateTime signingTime = DateTime.UtcNow;

            //Get the certs, crls and ocsps
            IX509Store certStore = null;
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            if (includeSigner)
            {
                //add the cached certificates
                certStore = senderChainStore;

                //add the CRLs & OCSPs if online
                if (!Settings.Default.Offline)
                {
                    ICollection certs = senderChainStore.GetMatches(null);
                    for (int i = 0; i < senderChainList.Count; i++)
                    {
                        BC::X509.X509Certificate cert = DotNetUtilities.FromX509Certificate(senderChainList[i]);
                        BC::X509.X509Certificate issuer = i + 1 >= senderChainList.Count ? null : DotNetUtilities.FromX509Certificate(senderChainList[i + 1]);
                        trace.TraceEvent(TraceEventType.Verbose, 0, "Adding OCSP or CRL for cert {0}", cert.SubjectDN.ToString());

                        //Lets start with the OCSP, which is smaller and more up to data
                        bool ocspPresent = RetreiveOcsps(ocsps, signingTime, cert, issuer);

                        //lets look for an CRL and use it if we did not find an OCPS
                        if (!ocspPresent) RetreiveCrls(crls, signingTime, cert, issuer);
                    }
                }
            }

            CmsSignedDataStreamGenerator signedGenerator = new CmsSignedDataStreamGenerator();
            
            //add the certificates
            if (certStore != null) signedGenerator.AddCertificates(certStore);

            //For compatibility we don't add it to the CMS (most implementations, including BC, don't support OCSP here)
            //IX509Store crlStore = X509StoreFactory.Create("CRL/COLLECTION", new X509CollectionStoreParameters(crls));
            //signedGenerator.AddCrls(crlStore);

            //add signed attributes to the signature (own signig time)
            IDictionary signedAttrDictionary = new Hashtable();
            BC::Asn1.Cms.Attribute signTimeattr = new BC::Asn1.Cms.Attribute(CmsAttributes.SigningTime,
                    new DerSet(new BC::Asn1.Cms.Time(DateTime.UtcNow)));
            signedAttrDictionary.Add(signTimeattr.AttrType, signTimeattr);
            BC::Asn1.Cms.AttributeTable signedAttrTable = new BC.Asn1.Cms.AttributeTable(signedAttrDictionary);

            //add unsigned attributes to signature (for OCSP & CRL)
            BC::Asn1.Cms.AttributeTable unsignedAttrTable = null;
            if (crls.Count > 0 || ocsps.Count > 0)
            {
                IDictionary unsignedAttrDictionary = new Hashtable();
                RevocationValues revocationValues = new RevocationValues(crls, ocsps, null);
                BC::Asn1.Cms.Attribute revocationAttr = 
                    new BC::Asn1.Cms.Attribute(EsfAttributes.RevocationValues, new DerSet(revocationValues.ToAsn1Object()));
                unsignedAttrDictionary.Add(revocationAttr.AttrType, revocationAttr);
                unsignedAttrTable = new BC.Asn1.Cms.AttributeTable(unsignedAttrDictionary);
            }

            //Add the signatures (moved below so it is easier to add unsigned attributes)
            SignatureAlgorithm signAlgo;
            if (((RSACryptoServiceProvider) sender.PrivateKey).CspKeyContainerInfo.Exportable) {
                signAlgo =  EteeActiveConfig.Seal.NativeSignatureAlgorithm;
                signedGenerator.AddSigner(DotNetUtilities.GetKeyPair(sender.PrivateKey).Private,
                    bcSender, signAlgo.EncryptionAlgorithm.Value, signAlgo.DigestAlgorithm.Value,
                    signedAttrTable, unsignedAttrTable);
            } else {
                signAlgo = EteeActiveConfig.Seal.WindowsSignatureAlgorithm;
                signedGenerator.AddSigner(new ProxyRsaKeyParameters((RSACryptoServiceProvider) sender.PrivateKey),
                    bcSender, signAlgo.EncryptionAlgorithm.Value, signAlgo.DigestAlgorithm.Value,
                    signedAttrTable, unsignedAttrTable);
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Added Signer [EncAlgo={0} ({1}), DigestAlgo={2} ({3})",
                signAlgo.EncryptionAlgorithm.FriendlyName,
                signAlgo.EncryptionAlgorithm.Value,
                signAlgo.DigestAlgorithm.FriendlyName,
                signAlgo.DigestAlgorithm.Value);

            Stream signingStream = signedGenerator.Open(signed, true);
            trace.TraceEvent(TraceEventType.Verbose, 0, "Create embedded signed message (still empty)");
            try
            {
                unsigned.CopyTo(signingStream);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Message copied and digest calculated");
            }
            finally
            {
                signingStream.Close();
                trace.TraceEvent(TraceEventType.Verbose, 0, "Signature block added");
            }
        }

        private void RetreiveCrls(IList<CertificateList> crls, DateTime signingTime, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer)
        {
            Asn1OctetString crlDPsBytes = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (crlDPsBytes != null)
            {
                CrlDistPoint crlDPs = CrlDistPoint.GetInstance(X509ExtensionUtilities.FromExtensionValue(crlDPsBytes));
                foreach (DistributionPoint dp in crlDPs.GetDistributionPoints())
                {
                    DistributionPointName dpn = dp.DistributionPointName;
                    if (dpn != null && dpn.PointType == DistributionPointName.FullName)
                    {
                        GeneralName[] genNames = GeneralNames.GetInstance(dpn.Name).GetNames();
                        foreach (GeneralName genName in genNames)
                        {
                            if (genName.TagNo == GeneralName.UniformResourceIdentifier)
                            {
                                //Found a CRL URL, lets get it.
                                string location = DerIA5String.GetInstance(genName.Name).GetString();

                                try
                                {
                                    //Make the Web request
                                    WebRequest crlRequest = WebRequest.Create(location);
                                    WebResponse crlResponse = crlRequest.GetResponse();

                                    //Parse the result
                                    X509Crl crl;
                                    CertificateList certList;
                                    using (crlResponse)
                                    {
                                        Asn1Sequence crlAns1 = (Asn1Sequence)Asn1Sequence.FromStream(crlResponse.GetResponseStream());
                                        certList = CertificateList.GetInstance(crlAns1);
                                        crl = new X509Crl(certList);
                                    }

                                    //Verify the result (no need to create a message that should not be accepted).
                                    CrlVerifier.Verify(crl, signingTime, cert, issuer, location);

                                    //All done, add it
                                    crls.Add(certList);
                                    trace.TraceEvent(TraceEventType.Verbose, 0, "Added CRL {0} to message", location);
                                }
                                catch (InvalidOperationException ioe)
                                {
                                    throw ioe;
                                }
                                catch (Exception)
                                {
                                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to retreive the CRL {0}", location);
                                }
                            }
                        }
                    }
                }
            }
        }

        private bool RetreiveOcsps(IList<BasicOcspResponse> ocsps, DateTime signingTime, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer)
        {
            Asn1OctetString ocspDPsBytes = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
            if (ocspDPsBytes != null)
            {
                AuthorityInformationAccess ocspAki = AuthorityInformationAccess.GetInstance(X509ExtensionUtilities.FromExtensionValue(ocspDPsBytes));
                foreach (AccessDescription ad in ocspAki.GetAccessDescriptions())
                {
                    if (AccessDescription.IdADOcsp.Equals(ad.AccessMethod) 
                        && ad.AccessLocation.TagNo == GeneralName.UniformResourceIdentifier)
                        {
                            //Found an OCSP URL, lets call it.
                            string location = DerIA5String.GetInstance(ad.AccessLocation.Name).GetString();

                            try
                            {
                                //Prepare the request
                                OcspReqGenerator ocspReqGen = new OcspReqGenerator();
                                ocspReqGen.AddRequest(new CertificateID(CertificateID.HashSha1, issuer, cert.SerialNumber));

                                //Make the request & sending it.
                                OcspReq ocspReq = ocspReqGen.Generate();
                                WebRequest ocspWebReq = WebRequest.Create(location);
                                ocspWebReq.Method = "POST";
                                ocspWebReq.ContentType = "application/ocsp-request";
                                Stream ocspWebReqStream = ocspWebReq.GetRequestStream();
                                ocspWebReqStream.Write(ocspReq.GetEncoded(), 0, ocspReq.GetEncoded().Length);
                                WebResponse ocspWebResp = ocspWebReq.GetResponse();

                                //Get the response (in "managed" and "raw" format)
                                OcspResp ocspResp;
                                OcspResponse ocspResponse;
                                using (ocspWebResp)
                                {
                                    ocspResponse = OcspResponse.GetInstance(new Asn1InputStream(ocspWebResp.GetResponseStream()).ReadObject());
                                    ocspResp = new OcspResp(ocspResponse);
                                }

                                //check if we got a valid OCSP, if not try CRL
                                if (ocspResp.Status == 0)
                                {
                                    //Get the basic response (in "managed" and "raw" format)
                                    BasicOcspResp basicOcspResp = (BasicOcspResp)ocspResp.GetResponseObject();
                                    BasicOcspResponse basicOcspResponse = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(ocspResponse.ResponseBytes.Response.GetOctets()));

                                    //Verify the OCSP before using it.
                                    OcspVerifier.Verify(basicOcspResp, signingTime, cert, issuer, location);

                                    ocsps.Add(basicOcspResponse);
                                    trace.TraceEvent(TraceEventType.Verbose, 0, "Added OCSP of {0} to message", location);
                                }
                            }
                            catch (InvalidOperationException ioe)
                            {
                                throw ioe;
                            }
                            catch (Exception)
                            {
                                trace.TraceEvent(TraceEventType.Warning, 0, "Failed to retreive the OCSP {0}", location);
                            }
                        }
                }
                return true;
            }
            else
            {
                return false;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        protected void Encrypt(Stream cipher, Stream clear, ICollection<EncryptionToken> tokens, SecretKey key)
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Encrypting message for {0} known and {1} unknown recipient",
                tokens == null ? 0 : tokens.Count, key == null ? 0 : 1);
            CmsEnvelopedDataStreamGenerator encryptGenerator = new CmsEnvelopedDataStreamGenerator();
            if (tokens != null)
            {
                foreach (EncryptionToken token in tokens)
                {
                    BC::X509.X509Certificate cert = token.ToBCCertificate();
                    encryptGenerator.AddKeyTransRecipient(cert);
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Added known recipient: {0}", cert.SubjectDN.ToString());
                }
            }
            if (key != null)
            {
                encryptGenerator.AddKekRecipient("AES", key.BCKey, key.Id);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Added unknown recipient [Algo={0}, keyId={1}]", "AES", key.IdString);
            }

            Stream encryptingStream = encryptGenerator.Open(cipher, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
            trace.TraceEvent(TraceEventType.Verbose, 0, "Create encrypted message (still empty) [EncAlgo={0} ({1})]",
                EteeActiveConfig.Seal.EncryptionAlgorithm.FriendlyName, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
            try
            {
                clear.CopyTo(encryptingStream);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Message encrypted");
            }
            finally
            {
                encryptingStream.Close();
                trace.TraceEvent(TraceEventType.Verbose, 0, "Recipient infos added");
            }
        }

    }
}
