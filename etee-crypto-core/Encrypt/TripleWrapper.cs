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

namespace Siemens.EHealth.Etee.Crypto.Encrypt
{
    internal class TripleWrapper : IDataSealer
    {
        /*
        private class SignParams
        {
            public SignParams(Stream signed, Stream unsigned, bool includeSigner)
            {
                this.signed = signed;
                this.unsigned = unsigned;
                this.includeSigner = includeSigner;
            }

            public Stream signed;
            
            public Stream unsigned;

            public bool includeSigner;

            public Exception exception;
        }

        private class EncryptParams
        {
            public EncryptParams(Stream cypher, Stream clear, ICollection<EncryptionToken> tokens, SecretKey key)
            {
                this.cypher = cypher;
                this.clear = clear;
                this.tokens = tokens;
                this.key = key;
            }

            public Stream cypher;
            
            public Stream clear;
            
            public ICollection<EncryptionToken> tokens;

            public SecretKey key;

            public Exception exception;
        }
         */

        //private Guid traceId = Guid.NewGuid();

        //private TraceSource trace = new TraceSource("EHealth.Etee");

        private X509Certificate2 sender;


        //private Thread innerSignatureThread;

        //private Thread encryptThread;

        //private Thread outerSignatureThread;

        internal TripleWrapper(X509Certificate2 sender)
        {
            this.sender = sender;
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
                MemoryStream sealedStream = (MemoryStream)SealSemiOptimized(factory, unsealedStream, tokens, null);
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
                MemoryStream sealedStream = (MemoryStream)SealSemiOptimized(factory, unsealedStream, tokens, null);
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
            return SealSemiOptimized(factory, unsealed, tokens, null);
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public Stream Seal(ReadOnlyCollection<EncryptionToken> tokens, Stream unsealed)
        {
            ITempStreamFactory factory = new TempFileStreamFactory();
            return SealSemiOptimized(factory, unsealed, tokens, null);
        }

        public byte[] Seal(byte[] unsealed, SecretKey key)
        {
            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)SealSemiOptimized(factory, unsealedStream, null, key);
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
            return SealSemiOptimized(factory, unsealed, tokens, key);
        }

        public byte[] Seal(ReadOnlyCollection<EncryptionToken> tokens, byte[] unsealed, SecretKey key)
        {
            ITempStreamFactory factory = new MemoryStreamFactory();
            MemoryStream unsealedStream = new MemoryStream(unsealed, false);
            using (unsealedStream)
            {
                MemoryStream sealedStream = (MemoryStream)SealSemiOptimized(factory, unsealedStream, tokens, key);
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
                return SealSemiOptimized(factory, unsealed, tokens, key);
            
        }

        #endregion

        private Stream SealSemiOptimized(ITempStreamFactory factory, Stream unsealedStream, ICollection<EncryptionToken> tokens, SecretKey key)
        {
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

                    signedEncrypted.Position = 0;

                    //This is the output, so we need to make it a temp stream (temp file or memory stream)
                    Stream sealedStream = factory.CreateNew();

                    //Outer sign
                    Sign(sealedStream, signedEncrypted, true);

                    sealedStream.Position = 0; //reset the stream

                    return sealedStream;
                }
            }
        }

        /*
        private Stream SealOptimized(ITempStreamFactory factory, Stream unsealedStream, ICollection<EncryptionToken> tokens, SecretKey key)
        {
            //Create pipe pair for inner signed stream
            AnonymousPipeServerStream signedServer = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
            using (signedServer)
            {
                AnonymousPipeClientStream signedClient = new AnonymousPipeClientStream(PipeDirection.In, signedServer.GetClientHandleAsString());
                using (signedClient)
                {
                    //Inner sign
                    SignParams inner = new SignParams(signedServer, unsealedStream, false);
                    innerSignatureThread.Start(inner);

                    //Create pipe pair for encrypted stresm
                    AnonymousPipeServerStream signedEncryptedServer = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
                    using (signedEncryptedServer)
                    {
                        AnonymousPipeClientStream signedEncryptedClient = new AnonymousPipeClientStream(PipeDirection.In, signedEncryptedServer.GetClientHandleAsString());
                        using (signedEncryptedClient)
                        {
                            //Encrypt
                            EncryptParams encrypt = new EncryptParams(signedEncryptedServer, signedClient, tokens, key);
                            encryptThread.Start(encrypt);

                            //This is the output, so we need to make it a temp stream (temp file or memory stream)
                            Stream sealedStream = factory.CreateNew();

                            //Outer sign
                            SignParams outer = new SignParams(sealedStream, signedEncryptedClient, true);
                            outerSignatureThread.Start(outer);

                            //Wait for all the threads to finish and check the results
                            innerSignatureThread.Join();
                            encryptThread.Join();
                            outerSignatureThread.Join();
                            if (inner.exception != null) throw new InvalidOperationException("Inner signature failed", inner.exception);
                            if (encrypt.exception != null) throw new InvalidOperationException("Encryption failed", encrypt.exception);
                            if (outer.exception != null) throw new InvalidOperationException("Outer signature failed", outer.exception);

                            sealedStream.Position = 0; //reset the stream

                            return sealedStream;
                        }
                    }
                }
            }
        }
         

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void Sign(Object data)
        {
            SignParams param = (SignParams)data;
            try
            {
                Sign(param.signed, param.unsigned, param.includeSigner);
            }
            catch (Exception e)
            {
                param.exception = e;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void Encrypt(Object data)
        {
            EncryptParams param = (EncryptParams)data;
            try
            {
                Encrypt(param.cypher, param.clear, param.tokens, param.key);
            }
            catch (Exception e)
            {
                param.exception = e;
            }
        }
         */

        protected void Sign(Stream signed, Stream unsigned, bool includeSigner)
        {
            BC::X509Certificate bcSender = DotNetUtilities.FromX509Certificate(sender);
            CmsSignedDataStreamGenerator signedGenerator = new CmsSignedDataStreamGenerator();
            signedGenerator.AddSigner(DotNetUtilities.GetKeyPair(sender.PrivateKey).Private,
                bcSender, EteeActiveConfig.Seal.SignatureAlgorithm.EncryptionAlgorithm.Value,
                EteeActiveConfig.Seal.SignatureAlgorithm.DigestAlgorithm.Value);
            if (includeSigner)
            {
                List<BC::X509Certificate> signerColl = new List<BC::X509Certificate>();
                signerColl.Add(bcSender);
                IX509Store signerBcColl = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(signerColl));
                signedGenerator.AddCertificates(signerBcColl);

            }
            Stream signingStream = signedGenerator.Open(signed, true);
            try
            {
                StreamUtils.Copy(unsigned, signingStream);
            }
            finally
            {
                signingStream.Close();
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
        protected void Encrypt(Stream cipher, Stream clear, ICollection<EncryptionToken> tokens, SecretKey key)
        {
            CmsEnvelopedDataStreamGenerator encryptGenerator = new CmsEnvelopedDataStreamGenerator();
            if (tokens != null)
            {
                foreach (EncryptionToken token in tokens)
                {
                    BC::X509Certificate cert = token.ToBCCertificate();
                    encryptGenerator.AddKeyTransRecipient(cert);
                }
            }
            if (key != null)
            {
                encryptGenerator.AddKekRecipient("AES", key.BCKey, key.Id);
            }

            Stream encryptingStream = encryptGenerator.Open(cipher, EteeActiveConfig.Seal.EncryptionAlgorithm.Value);
            try
            {
                StreamUtils.Copy(clear, encryptingStream);
            }
            finally
            {
                encryptingStream.Close();
            }
        }

    }
}
