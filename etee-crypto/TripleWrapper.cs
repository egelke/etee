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

using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Store;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Utils;
using BC = Org.BouncyCastle;
using System;
using System.Security.Cryptography;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Cms;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Tsp;
using Egelke.EHealth.Etee.Crypto.Store;
using Egelke.EHealth.Etee.Crypto.Sender;
using System.Linq;
using Org.BouncyCastle.Crypto.Operators;

#if NETFRAMEWORK
using System.Diagnostics;
#else
using Microsoft.Extensions.Logging;
#endif


namespace Egelke.EHealth.Etee.Crypto
{
    internal class TripleWrapper : IDataSealer, IDataCompleter, ITmaDataCompleter
    {
#if NETFRAMEWORK
        private readonly TraceSource trace = new TraceSource("Egelke.EHealth.Etee");
#else
        private readonly ILogger logger;
#endif

        private Level level;

        //The sender authentication certificate
        private X509Certificate2 authentication;

        //The sender signature certificate
        private X509Certificate2 signature;

        private WebKey ownWebKey;

        private ITimestampProvider timestampProvider;

        private X509Certificate2Collection extraStore;

        internal TripleWrapper(
#if !NETFRAMEWORK
            ILoggerFactory loggerFactory,
#endif
            Level level, WebKey ownWebKey, ITimestampProvider timestampProvider) {
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("level", "Only levels B, T, LT and LTA are allowed");

#if !NETFRAMEWORK
            logger = loggerFactory.CreateLogger("Egelke.EHealth.Etee");
#endif
            this.level = level;
            this.ownWebKey = ownWebKey;
            this.timestampProvider = timestampProvider;
        }

        internal TripleWrapper(
#if !NETFRAMEWORK
            ILoggerFactory loggerFactory,
#endif
            Level level, X509Certificate2 authentication, X509Certificate2 signature, ITimestampProvider timestampProvider, X509Certificate2Collection extraStore)
        {
            //basic checks
            if (level == Level.L_Level || level == Level.A_level) throw new ArgumentException("level", "Only levels B, T, LT and LTA are allowed");

#if !NETFRAMEWORK
            logger = loggerFactory.CreateLogger("Egelke.EHealth.Etee");
#endif
            this.level = level;
            this.signature = signature;
            this.authentication = authentication;
            this.timestampProvider = timestampProvider;
            this.extraStore = extraStore;
        }

        #region DataCompleter Members

        public Stream Complete(Stream sealedData)
        {
            TimemarkKey timemarkKey;
            return Complete(sealedData, out timemarkKey);
        }

        public Stream Complete(Stream sealedData, out TimemarkKey timemarkKey)
        {
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Completing the provided sealed message with revocation and time info according to the level {0}", this.level);
#else
            logger.LogInformation("Completing the provided sealed message with revocation and time info according to the level {0}", this.level);
#endif

            ITempStreamFactory factory = NewFactory(sealedData);
            Stream completed = factory.CreateNew();
            Complete(this.level, completed, sealedData, null, null, out timemarkKey);
            completed.Position = 0;

            return completed;
        }

        #endregion

        #region DataSealer Members

        public Stream Seal(Stream unsealed, params EncryptionToken[] tokens)
        {
            return Seal(unsealed, null, tokens);
        }

        public Stream Seal(Stream unsealed, params X509Certificate2[] certs)
        {
            ITempStreamFactory factory = NewFactory(unsealed);
            return Seal(factory, unsealed, null, certs, null);
        }

        public Stream Seal(Stream unsealed, params WebKey[] webKeys)
        {
            return Seal(unsealed, null, null, webKeys);
        }

        public Stream Seal(Stream unsealed, SecretKey key, params EncryptionToken[] tokens)
        {
            return Seal(unsealed, key, tokens, null);
        }

        public Stream Seal(Stream unsealed, SecretKey key, EncryptionToken[] tokens, WebKey[] webKeys)
        {
            ITempStreamFactory factory = NewFactory(unsealed);
            return Seal(factory, unsealed, key, tokens == null ? null : ConverToX509Certificates(tokens), webKeys);
        }

        #endregion

        private ITempStreamFactory NewFactory(Stream stream)
        {
            return stream.Length > Settings.Default.InMemorySize ? (ITempStreamFactory)new TempFileStreamFactory() : (ITempStreamFactory)new MemoryStreamFactory();
        }

        private X509Certificate2[] ConverToX509Certificates(EncryptionToken[] tokens)
        {
            X509Certificate2[] certs = new X509Certificate2[tokens.Length];
            for (int i = 0; i < tokens.Length; i++)
            {
                certs[i] = tokens[i].ToCertificate();
            }
            return certs;
        }

        private Stream Seal(ITempStreamFactory factory, Stream unsealedStream, SecretKey skey, X509Certificate2[] certs, WebKey[] webKeys)
        {
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Sealing message of {0} bytes for {1}/{2} known recipients and {3} unknown recipients to level {3}",
                unsealedStream.Length, certs?.Length, webKeys?.Length, skey == null ? 0 : 1, this.level);
#else
            logger.LogInformation("Sealing message of {0} bytes for {1}/{2} known recipients and {3} unknown recipients to level {3}",
                unsealedStream.Length, certs?.Length, webKeys?.Length, skey == null ? 0 : 1, this.level);
#endif

            using (
                Stream innerDetached = new MemoryStream(),
                    innerEmbedded = factory.CreateNew(),
                    encrypted = factory.CreateNew(),
                    outerDetached = new MemoryStream()
            )
            {
                TimemarkKey timemarkKey;

                //Inner sign
                if (signature != null)
                    SignDetached(innerDetached, unsealedStream, signature);
                else if (ownWebKey != null)
                    SignDetached(innerDetached, unsealedStream, ownWebKey.BCKeyPair, ownWebKey.Id);
                else
                    throw new InvalidOperationException("Tripple wrapper must have either cert of keypair for signing");

                //prepare to merge the detached inner signature with its content
                innerDetached.Position = 0;
                unsealedStream.Position = 0;

                //embed the content in the inner signature and add any required info if it uses a different cert.
                Complete(signature == authentication ? (Level?) null : this.level & ~Level.T_Level, innerEmbedded, innerDetached, unsealedStream, signature, out timemarkKey);

                //prepare to encrypt
                innerEmbedded.Position = 0;

                //Encrypt
                Encrypt(encrypted, innerEmbedded, certs, skey, webKeys);

                //Loop, since eID doesn't like to be use in very short succession
                int retry = 0;
                bool success = false;
                while (!success)
                {
                    //prepare to create the outer signature
                    encrypted.Position = 0;
                    outerDetached.SetLength(0);

                    try
                    {
                        //Create the outer signature
                        if (signature != null)
                            SignDetached(outerDetached, encrypted, authentication);
                        else
                            SignDetached(outerDetached, encrypted, ownWebKey.BCKeyPair, ownWebKey.Id);
                        success = true;
                    }
                    catch (CryptographicException ce)
                    {
                        if (retry++ < 4)
                        {
#if NETFRAMEWORK
                            trace.TraceEvent(TraceEventType.Warning, 0, "Failed to put outer signature, staring loop: {0}", ce);
#else
                            logger.LogWarning("Failed to put outer signature, staring loop: {0}", ce);
#endif
                            System.Threading.Thread.Sleep((int)Math.Pow(10, retry));
                        }
                        else
                        {
                            throw ce;
                        }
                    }
                }

                //prepare to merge the detached inner signature with its content
                encrypted.Position = 0;
                outerDetached.Position = 0;

                //embed the content in the out signature and add any required info
                Stream result = factory.CreateNew();
                Complete(this.level, result, outerDetached, encrypted, authentication, out timemarkKey);

                //prepare to return the triple wrapped message
                result.Position = 0;

                //return the triple wrapped message
                return result;
            }
        }

        protected void SignDetached(Stream signed, Stream unsigned, X509Certificate2 selectedCert)
        {
            BC::X509.X509Certificate bcSelectedCert = DotNetUtilities.FromX509Certificate(selectedCert);
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Signing the message in name of {0}", selectedCert.Subject);
#else
            logger.LogInformation("Signing the message in name of {0}", selectedCert.Subject);
#endif

            BC.Crypto.ISignatureFactory sigFactory;
            try
            {
                SignatureAlgorithm signAlgo = EteeActiveConfig.Seal.NativeSignatureAlgorithm;
                BC::Crypto.AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(selectedCert.PrivateKey);
                sigFactory = new Asn1SignatureFactory(signAlgo.Algorithm.FriendlyName, keyPair.Private);
            }
            catch (CryptographicException)
            { 
                SignatureAlgorithm signAlgo = EteeActiveConfig.Seal.WindowsSignatureAlgorithm;
                sigFactory = new WinSignatureFactory(signAlgo.Algorithm, signAlgo.DigestAlgorithm, selectedCert.PrivateKey);
            }

            SignerInfoGenerator sigInfoGen = new SignerInfoGeneratorBuilder()
                .Build(sigFactory, bcSelectedCert);

            CmsSignedDataGenerator cmsSignedDataGen = new CmsSignedDataGenerator();
            cmsSignedDataGen.AddSignerInfoGenerator(sigInfoGen);

            CmsSignedData detachedSignature = cmsSignedDataGen.Generate(new CmsProcessableProxy(unsigned), false);

            byte[] detachedSignatureBytes = detachedSignature.GetEncoded();
            signed.Write(detachedSignatureBytes, 0, detachedSignatureBytes.Length);
        }

        protected void SignDetached(Stream signed, Stream unsigned, BC::Crypto.AsymmetricCipherKeyPair bcKeyPair, byte[] keyId)
        {
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Signing the message in name of {0}", Convert.ToBase64String(keyId));
#else
            logger.LogInformation("Signing the message in name of {0}", Convert.ToBase64String(keyId));
#endif

            SignatureAlgorithm signAlgo = EteeActiveConfig.Seal.NativeSignatureAlgorithm;
            var sigFactory = new Asn1SignatureFactory(signAlgo.Algorithm.FriendlyName, bcKeyPair.Private);

            SignerInfoGenerator sigInfoGen = new SignerInfoGeneratorBuilder()
                .Build(sigFactory, keyId);

            CmsSignedDataGenerator cmsSignedDataGen = new CmsSignedDataGenerator();
            cmsSignedDataGen.AddSignerInfoGenerator(sigInfoGen);

            CmsSignedData detachedSignature = cmsSignedDataGen.Generate(new CmsProcessableProxy(unsigned), false);

            byte[] detachedSignatureBytes = detachedSignature.GetEncoded();
            signed.Write(detachedSignatureBytes, 0, detachedSignatureBytes.Length);
        }

        protected void Encrypt(Stream cipher, Stream clear, ICollection<X509Certificate2> certs, SecretKey key, WebKey[] webKeys)
        {
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Encrypting message for {0} known and {1} unknown recipient",
                certs == null ? 0 : certs.Count, key == null ? 0 : 1);
#else
            logger.LogInformation("Encrypting message for {0} known and {1} unknown recipient",
                certs == null ? 0 : certs.Count, key == null ? 0 : 1);
#endif
            CmsEnvelopedDataStreamGenerator encryptGenerator = new CmsEnvelopedDataStreamGenerator();
            if (certs != null)
            {
                foreach (X509Certificate2 cert in certs)
                {
                    BC::X509.X509Certificate bcCert = DotNetUtilities.FromX509Certificate(cert);
                    encryptGenerator.AddKeyTransRecipient(bcCert);
#if NETFRAMEWORK
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Added known recipient: {0} ({1})", bcCert.SubjectDN.ToString(), bcCert.IssuerDN.ToString());
#else
                    logger.LogDebug("Added known recipient: {0} ({1})", bcCert.SubjectDN.ToString(), bcCert.IssuerDN.ToString());
#endif
                }
            }
            if (key != null)
            {
                encryptGenerator.AddKekRecipient("AES", key.BCKey, key.Id);
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "Added unknown recipient [Algorithm={0}, keyId={1}]", "AES", key.IdString);
#else
                logger.LogDebug("Added unknown recipient [Algorithm={0}, keyId={1}]", "AES", key.IdString);
#endif
            }
            if (webKeys != null)
            {
                foreach(WebKey webKey in webKeys)
                {
                    encryptGenerator.AddKeyTransRecipient(webKey.BCPublicKey, webKey.Id);
#if NETFRAMEWORK
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Added web recipient [Algorithm={0}, keyId={1}]", "RSA", webKey.IdString);
#else
                    logger.LogDebug("Added web recipient [Algorithm={0}, keyId={1}]", "RSA", webKey.IdString);
#endif
                }
            }

            Stream encryptingStream = encryptGenerator.Open(cipher, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Create encrypted message (still empty) [EncAlgo={0} ({1})]",
                EteeActiveConfig.Seal.EncryptionAlgorithm.FriendlyName, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
#else
            logger.LogDebug("Create encrypted message (still empty) [EncAlgo={0} ({1})]",
                EteeActiveConfig.Seal.EncryptionAlgorithm.FriendlyName, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
#endif
            try
            {
                clear.CopyTo(encryptingStream);
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "Message encrypted");
#else
                logger.LogDebug("Message encrypted");
#endif
            }
            finally
            {
                encryptingStream.Close();
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "Recipient infos added");
#else
                logger.LogDebug("Recipient infos added");
#endif
            }
        }

        protected void Complete(Level? level, Stream embedded, Stream signed, Stream content, X509Certificate2 providedSigner, out TimemarkKey timemarkKey)
        {
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Information, 0, "Completing the message with of {0} bytes to level {1}", signed.Length, level);
#else
            logger.LogInformation("Completing the message with of {0} bytes to level {1}", signed.Length, level);
#endif

            //Create the objects we need
            var gen = new CmsSignedDataStreamGenerator();
            var parser = new CmsSignedDataParser(signed);
            timemarkKey = new TimemarkKey();

            //preset the digests so we can add the signers afterwards
            gen.AddDigests(parser.DigestOids);

            //Copy the content to the output
            Stream contentOut = gen.Open(embedded, parser.SignedContentType.Id, true);
            if (content != null)
                content.CopyTo(contentOut);
            else
                parser.GetSignedContent().ContentStream.CopyTo(contentOut);

            //Extract the various data from outer layer
            SignerInformation signerInfo = ExtractSignerInfo(parser);
            IX509Store embeddedCerts = parser.GetCertificates("Collection");

            //Extract the various data from signer info
            timemarkKey.SignatureValue = signerInfo.GetSignature();
            timemarkKey.SigningTime = ExtractSigningTime(signerInfo);
            timemarkKey.Signer = ExtractSignerCert(embeddedCerts, signerInfo, providedSigner);
            if (timemarkKey.Signer != null)
                timemarkKey.SignerId = DotNetUtilities.FromX509Certificate(timemarkKey.Signer).GetSubjectKeyIdentifier();
            else
                timemarkKey.SignerId = signerInfo.SignerID.ExtractSignerId();

            //Extract the various data from unsiged attributes of signer info
            IDictionary unsignedAttributes = signerInfo.UnsignedAttributes != null ? signerInfo.UnsignedAttributes.ToDictionary() : new Hashtable();
            TimeStampToken tst = ExtractTimestamp(unsignedAttributes);
            RevocationValues revocationInfo = ExtractRevocationInfo(unsignedAttributes);

            //quick check for an expected error and extrapolate some info
            if (timemarkKey.SignerId == null)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "We could not find any signer information");
#else
                logger.LogError("We could not find any signer information");
#endif
                throw new InvalidMessageException("The message does not contain any valid signer info");
            }

            if (timemarkKey.SigningTime == default && tst != null)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Information, 0, "Implicit signing time is replaced with time-stamp time {1}", tst.TimeStampInfo.GenTime);
#else
                logger.LogInformation("Implicit signing time is replaced with time-stamp time {1}", tst.TimeStampInfo.GenTime);
#endif
                timemarkKey.SigningTime = tst.TimeStampInfo.GenTime;
            }

            //Are we missing embedded certs and should we add them?
            if ((embeddedCerts == null || embeddedCerts.GetMatches(null).Count <= 1)
                && timemarkKey.Signer != null
                && level != null)
            {
                embeddedCerts = GetEmbeddedCerts(timemarkKey);
            }
            if (embeddedCerts != null) gen.AddCertificates(embeddedCerts); //add the existing or new embedded certs to the output.


            //Are we missing timestamp and should we add them (not that time-mark authorities do not require a timestamp provider)
            if (tst == null
                && (level & Level.T_Level) == Level.T_Level && timestampProvider != null)
            {
                tst = GetTimestamp(timemarkKey);
                AddTimestamp(unsignedAttributes, tst);
            }

            //should be make sure we have the proper revocation info (it is hard to tell if we have everything, just go for it)
            if ((level & Level.L_Level) == Level.L_Level)
            {
                if (embeddedCerts != null && embeddedCerts.GetMatches(null).Count > 0)
                {
                    //extend the revocation info with info about the embedded certs
                    revocationInfo = GetRevocationValues(timemarkKey, embeddedCerts, revocationInfo);
                }
                if (tst != null)
                {
                    //extend the revocation info with info about the TST
                    revocationInfo = GetRevocationValues(tst, revocationInfo);
                }
                //update the unsigned attributes
                AddRevocationValues(unsignedAttributes, revocationInfo);
            }

            //Update the unsigned attributes of the signer info
            signerInfo = SignerInformation.ReplaceUnsignedAttributes(signerInfo, new BC::Asn1.Cms.AttributeTable(unsignedAttributes));

            //Copy the signer
            gen.AddSigners(new SignerInformationStore(new SignerInformation[] { signerInfo }));

            contentOut.Close();
        }

        private SignerInformation ExtractSignerInfo(CmsSignedDataParser parser)
        {
            //Extract the signer info
            SignerInformationStore signerInfoStore = parser.GetSignerInfos();
            if (signerInfoStore.Count != 1)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "The message to complete does not contain a single signature");
#else
                logger.LogError("The message to complete does not contain a single signature");
#endif
                throw new InvalidMessageException("The message does not contain a single signature");
            }

            return signerInfoStore.GetSigners().Cast<SignerInformation>().First();
        }

        private DateTime ExtractSigningTime(SignerInformation signerInfo)
        {
            BC::Asn1.Cms.Attribute singingTimeAttr = signerInfo.SignedAttributes?[CmsAttributes.SigningTime];
            if (singingTimeAttr != null)
            {
                DateTime date = new BC::Asn1.Cms.Time(((DerSet)singingTimeAttr.AttrValues)[0].ToAsn1Object()).Date;
                if (date.Kind == DateTimeKind.Unspecified)
                {
                    return new DateTime(date.Ticks, DateTimeKind.Utc);
                }
                else
                {
                    return date.ToUniversalTime();
                }
            }
            else
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Warning, 0, "The message to complete does not contain a signing time");
#else
                logger.LogWarning("The message to complete does not contain a signing time");
#endif
                return default;
            }
        }

        private X509Certificate2 ExtractSignerCert(IX509Store embeddedCerts, SignerInformation signerInfo, X509Certificate2 provided)
        {
            //Extract the signer, if available
            if (embeddedCerts != null && embeddedCerts.GetMatches(null).Count > 0)
            {
                IEnumerator signerCerts = embeddedCerts.GetMatches(signerInfo.SignerID).GetEnumerator();
                if (!signerCerts.MoveNext())
                {
#if NETFRAMEWORK
                    trace.TraceEvent(TraceEventType.Error, 0, "The message does contains certificates, but the signing certificate is missing");
#else
                    logger.LogError("The message does contains certificates, but the signing certificate is missing");
#endif
                    throw new InvalidMessageException("The message does not contain the signer certificate");
                }
                var signer = new X509Certificate2(((BC::X509.X509Certificate)signerCerts.Current).GetEncoded());
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "The message contains certificates, of which {0} is the signer", signer.Subject);
#else
                logger.LogDebug("The message contains certificates, of which {0} is the signer", signer.Subject);
#endif
                //maybe (one day) check if the found signer corresponds to the provided signer)
                return signer;
            }
            else
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "The message does not contains certificates, adding the provided {0}", provided?.Subject);
#else
                logger.LogDebug("The message does not contains certificates, adding the provided {0}", provided?.Subject);
#endif
                return provided;
            }
        }

        

        private TimeStampToken ExtractTimestamp(IDictionary unsignedAttributes)
        {
            TimeStampToken tst = null;
            BC::Asn1.Cms.Attribute timestampAttr = (BC::Asn1.Cms.Attribute)unsignedAttributes[PkcsObjectIdentifiers.IdAASignatureTimeStampToken];
            if (timestampAttr != null && ((DerSet)timestampAttr.AttrValues).Count > 0)
            {
                DerSet rawTsts = (DerSet)timestampAttr.AttrValues;
                if (rawTsts.Count > 1)
                {
#if NETFRAMEWORK
                    trace.TraceEvent(TraceEventType.Error, 0, "There are {0} signature timestamps present", rawTsts.Count);
#else
                    logger.LogError("There are {0} signature timestamps present", rawTsts.Count);
#endif
                    throw new NotSupportedException("The library does not support more then one time-stamp");
                }

                tst = rawTsts[0].GetEncoded().ToTimeStampToken();
            }
            return tst;
        }

        private RevocationValues ExtractRevocationInfo(IDictionary unsignedAttributes)
        {
            BC::Asn1.Cms.Attribute revocationAttr = (BC::Asn1.Cms.Attribute)unsignedAttributes[PkcsObjectIdentifiers.IdAAEtsRevocationValues];
            if (revocationAttr != null)
            {
                DerSet revocationInfoSet = (DerSet)revocationAttr.AttrValues;
                if (revocationInfoSet == null || revocationInfoSet.Count == 0)
                {
                    return RevocationValues.GetInstance(revocationInfoSet[0]);
                }
            }
            return new RevocationValues(new CertificateList[0], new BasicOcspResponse[0], null);
        }

        private IX509Store GetEmbeddedCerts(TimemarkKey timemarkKey)
        {
            //Construct the chain of certificates
            Chain chain = timemarkKey.Signer.BuildChain(timemarkKey.SigningTime == default ? DateTime.UtcNow : timemarkKey.SigningTime, extraStore);
            if (chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "The certification chain of {0} failed with errors", chain.ChainElements[0].Certificate.Subject);
#else
                logger.LogError("The certification chain of {0} failed with errors", chain.ChainElements[0].Certificate.Subject);
#endif
                throw new InvalidMessageException(string.Format("The certificate chain of the signer {0} fails basic validation", timemarkKey.Signer.Subject));
            }

            List<BC::X509.X509Certificate> senderChainCollection = new List<BC::X509.X509Certificate>();
            foreach (ChainElement ce in chain.ChainElements)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Verbose, 0, "Adding the certificate {0} to the message", ce.Certificate.Subject);
#else
                logger.LogDebug("Adding the certificate {0} to the message", ce.Certificate.Subject);
#endif
                senderChainCollection.Add(DotNetUtilities.FromX509Certificate(ce.Certificate));
            }
            return X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(senderChainCollection));
        }

        private void AddEmbeddedCerts(CmsSignedDataStreamGenerator gen, IX509Store embeddedCerts)
        {
            if (embeddedCerts != null) gen.AddCertificates(embeddedCerts);
        }

        private TimeStampToken GetTimestamp(TimemarkKey timemarkKey)
        {
            SHA256 sha = SHA256.Create();
            byte[] signatureHash = sha.ComputeHash(timemarkKey.SignatureValue);
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "SHA-256 hashed the signature value from {0} to {1}", Convert.ToBase64String(timemarkKey.SignatureValue), Convert.ToBase64String(signatureHash));
#else
            logger.LogDebug("SHA-256 hashed the signature value from {0} to {1}", Convert.ToBase64String(timemarkKey.SignatureValue), Convert.ToBase64String(signatureHash));
#endif

            byte[] rawTst = timestampProvider.GetTimestampFromDocumentHash(signatureHash, "http://www.w3.org/2001/04/xmlenc#sha256");
            TimeStampToken tst = rawTst.ToTimeStampToken();

            //basic check
            if (!tst.IsMatch(new MemoryStream(timemarkKey.SignatureValue)))
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "The time-stamp does not correspond to the signature value {0}", Convert.ToBase64String(timemarkKey.SignatureValue));
#else
                logger.LogError("The time-stamp does not correspond to the signature value {0}", Convert.ToBase64String(timemarkKey.SignatureValue));
#endif
                throw new InvalidOperationException("The time-stamp authority did not return a matching time-stamp");
            }

            //Don't verify the time-stamp, it is done later
            return tst;
        }

        private void AddTimestamp(IDictionary unsignedAttributes, TimeStampToken tst)
        {
            byte[] rawTst = tst.GetEncoded();
            BC.Asn1.Cms.Attribute signatureTstAttr = new BC::Asn1.Cms.Attribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, new DerSet(Asn1Object.FromByteArray(rawTst)));
            unsignedAttributes[signatureTstAttr.AttrType] = signatureTstAttr;
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Added the time-stamp {0} [Token={1}]", tst.TimeStampInfo.GenTime, Convert.ToBase64String(rawTst));
#else
            logger.LogDebug("Added the time-stamp {0} [Token={1}]", tst.TimeStampInfo.GenTime, Convert.ToBase64String(rawTst));
#endif
        }

        private RevocationValues GetRevocationValues(TimemarkKey timemarkKey, IX509Store embeddedCerts, RevocationValues revocationInfo)
        {
            IList<CertificateList> crls = new List<CertificateList>(revocationInfo.GetCrlVals());
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>(revocationInfo.GetOcspVals());
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Start getting revocation values for Cert, having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#else
            logger.LogDebug("Start getting revocation values for Cert, having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#endif

            var chainExtraStore = new X509Certificate2Collection();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in embeddedCerts.GetMatches(null))
            {
                chainExtraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }
            Chain chain = timemarkKey.Signer.BuildChain(timemarkKey.SigningTime, chainExtraStore, crls, ocsps);
            if (chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "The certificate chain of the signer {0} failed with {1} issues: {2}, {3}", timemarkKey.Signer.Subject,
                    chain.ChainStatus.Count, chain.ChainStatus[0].Status, chain.ChainStatus[0].StatusInformation);
#else
                logger.LogError("The certificate chain of the signer {0} failed with {1} issues: {2}, {3}", timemarkKey.Signer.Subject,
                    chain.ChainStatus.Count, chain.ChainStatus[0].Status, chain.ChainStatus[0].StatusInformation);
#endif
                throw new InvalidMessageException(string.Format("The certificate chain of the signer {0} fails revocation validation", timemarkKey.Signer.Subject));
            }
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Finished getting revocation values for Cert, now having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#else
            logger.LogDebug("Finished getting revocation values for Cert, now having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#endif
            return new RevocationValues(crls, ocsps, null);
        }

        private RevocationValues GetRevocationValues(TimeStampToken tst, RevocationValues revocationInfo)
        {
            IList<CertificateList> crls = new List<CertificateList>(revocationInfo.GetCrlVals());
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>(revocationInfo.GetOcspVals());
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Start getting revocation values for TST, having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#else
            logger.LogDebug("Start getting revocation values for TST, having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#endif

            Timestamp ts = tst.Validate(crls, ocsps);
            if (ts.TimestampStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
            {
#if NETFRAMEWORK
                trace.TraceEvent(TraceEventType.Error, 0, "The certificate chain of the time-stamp signer {0} failed with {1} issues: {2}, {3}", ts.CertificateChain.ChainElements[0].Certificate.Subject,
                ts.TimestampStatus.Count, ts.TimestampStatus[0].Status, ts.TimestampStatus[0].StatusInformation);
#else
                logger.LogError("The certificate chain of the time-stamp signer {0} failed with {1} issues: {2}, {3}", ts.CertificateChain.ChainElements[0].Certificate.Subject,
                ts.TimestampStatus.Count, ts.TimestampStatus[0].Status, ts.TimestampStatus[0].StatusInformation);
#endif
                throw new InvalidMessageException("The embedded time-stamp fails validation");
            }
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Finished getting revocation values for TST, now having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#else
            logger.LogDebug("Finished getting revocation values for TST, now having {0} OCSP's and {1} CRL's", ocsps.Count, crls.Count);
#endif
            return new RevocationValues(crls, ocsps, null);
        }

        private void AddRevocationValues(IDictionary unsignedAttributes, RevocationValues revocationInfo)
        {
            BC::Asn1.Cms.Attribute revocationAttr = new BC::Asn1.Cms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new DerSet(revocationInfo.ToAsn1Object()));
            unsignedAttributes[revocationAttr.AttrType] = revocationAttr;
#if NETFRAMEWORK
            trace.TraceEvent(TraceEventType.Verbose, 0, "Added OCSP's and CRL's to the message");
#else
            logger.LogDebug("Added OCSP's and CRL's to the message");
#endif
        }
    }
}
