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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Store;
using Siemens.EHealth.Etee.Crypto.Configuration;
using Siemens.EHealth.Etee.Crypto.Utils;
using BC = Org.BouncyCastle.X509;
using System.Security.Permissions;
using System;
using System.Threading;
using System.Diagnostics;
using Org.BouncyCastle.Asn1.X509;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

namespace Siemens.EHealth.Etee.Crypto.Encrypt
{
    internal class TripleWrapper : IDataSealer
    {
        private TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

        private X509Certificate2 sender;

        private IX509Store senderChain;

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

            X509ChainElementEnumerator chainEnum = chain.ChainElements.GetEnumerator();
            List<BC::X509Certificate> bcChainList = new List<BC::X509Certificate>();
            while (chainEnum.MoveNext())
            {
                bcChainList.Add(DotNetUtilities.FromX509Certificate(chainEnum.Current.Certificate));
            }
            senderChain = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(bcChainList));
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
            BC::X509Certificate bcSender = DotNetUtilities.FromX509Certificate(sender);
            trace.TraceEvent(TraceEventType.Information, 0, "Signing the message in name of {0}", bcSender.SubjectDN.ToString());
            CmsSignedDataStreamGenerator signedGenerator = new CmsSignedDataStreamGenerator();
            SignatureAlgorithm signAlgo;
            if (((RSACryptoServiceProvider) sender.PrivateKey).CspKeyContainerInfo.Exportable) {
                signAlgo =  EteeActiveConfig.Seal.NativeSignatureAlgorithm;
                signedGenerator.AddSigner(DotNetUtilities.GetKeyPair(sender.PrivateKey).Private,
                    bcSender, signAlgo.EncryptionAlgorithm.Value, signAlgo.DigestAlgorithm.Value);
            } else {
                signAlgo = EteeActiveConfig.Seal.WindowsSignatureAlgorithm;
                signedGenerator.AddSigner(new ProxyRsaKeyParameters((RSACryptoServiceProvider) sender.PrivateKey),
                    bcSender, signAlgo.EncryptionAlgorithm.Value, signAlgo.DigestAlgorithm.Value);
            }
            trace.TraceEvent(TraceEventType.Verbose, 0, "Added Signer [EncAlgo={0} ({1}), DigestAlgo={2} ({3})",
                signAlgo.EncryptionAlgorithm.FriendlyName,
                signAlgo.EncryptionAlgorithm.Value,
                signAlgo.DigestAlgorithm.FriendlyName,
                signAlgo.DigestAlgorithm.Value);
            if (includeSigner)
            {
                signedGenerator.AddCertificates(senderChain);
                trace.TraceEvent(TraceEventType.Verbose, 0, "Added signing certificate to the messages");
            }
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
                    BC::X509Certificate cert = token.ToBCCertificate();
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
