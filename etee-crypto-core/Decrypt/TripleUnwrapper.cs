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

namespace Siemens.EHealth.Etee.Crypto.Decrypt
{
    internal class TripleUnwrapper : IDataUnsealer
    {
        
        private class VerifyParams
        {
            public VerifyParams(Stream verifiedContent, Stream signed, bool optimize, bool wait)
            {
                this.verifiedContent = verifiedContent;
                this.signed = signed;
                this.optimized = optimize;
                this.wait = wait;
            }

            public Stream verifiedContent;
            public Stream signed;
            public bool optimized;
            public bool wait;
            public SecurityInformation result;
            public Exception exception;
        }

        private class DecryptParams
        {
            public DecryptParams(Stream clear, Stream cypher, SecretKey key, bool optimized)
            {
                this.clear = clear;
                this.cypher = cypher;
                this.key = key;
                this.optimized = optimized;
            }

            public Stream clear;
            public Stream cypher;
            public SecretKey key;
            public bool optimized;
            public SecurityInformation result;
            public Exception exception;
        }

        private X509Certificate2 enc;

        private X509Certificate2 auth;

        private Thread innerSignatureThread;

        private Thread decryptThread;

        private Thread outerSignatureThread;

        private CertificateSecurityInformation overrideOrigine;

        private ManualResetEvent overrideOrigineMutex = new ManualResetEvent(false);

        internal TripleUnwrapper(X509Certificate2 enc, X509Certificate2 auth)
        {
            this.enc = enc;
            this.auth = auth;
            this.innerSignatureThread = new Thread(this.Verify);
            this.decryptThread = new Thread(this.Decrypt);
            this.outerSignatureThread = new Thread(this.Verify);
        }

        #region DataUnsealer Members

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public UnsealResult Unseal(Stream sealedData)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");

            try
            {
                return UnsealSemiOptimized(new TempFileStreamFactory(), sealedData, null);
            }
            catch (NotSupportedException)
            {
                //Start over, non optimize
                sealedData.Position = 0;
                return Unseal(new TempFileStreamFactory(), sealedData, null);
            }
        }

        public UnsealResult Unseal(byte[] sealedData)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");

            //No need to optimize for small files that fit in the memory
            MemoryStream tmp = new MemoryStream(sealedData);
            using (tmp)
            {
                return Unseal(new MemoryStreamFactory(), tmp, null);
            }
        }

        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        public UnsealResult Unseal(Stream sealedData, SecretKey key)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");
            if (key == null) throw new ArgumentNullException("key");

            try
            {
                return UnsealSemiOptimized(new TempFileStreamFactory(), sealedData, key);
            }
            catch (NotSupportedException)
            {
                //Start over, non optimize
                sealedData.Position = 0;
                return Unseal(new TempFileStreamFactory(), sealedData, key);
            }
        }

        public UnsealResult Unseal(byte[] sealedData, SecretKey key)
        {
            if (sealedData == null) throw new ArgumentNullException("sealedData");
            if (key == null) throw new ArgumentNullException("key");

            MemoryStream tmp = new MemoryStream(sealedData);
            using (tmp)
            {
                return Unseal(new MemoryStreamFactory(), tmp, key);
            }
            
        }

        #endregion

        private UnsealResult UnsealSemiOptimized(ITempStreamFactory factory, Stream sealedData, SecretKey key)
        {
            overrideOrigine = null;
            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();

            Stream verified = factory.CreateNew();
            using (verified)
            {
                result.SecurityInformation.OuterSignature = Verify(verified, sealedData, true, false);
                overrideOrigine = result.SecurityInformation.OuterSignature.Subject;

                verified.Position = 0; //reset the stream

                Stream decryptedVerified = factory.CreateNew();
                using (decryptedVerified)
                {
                    result.SecurityInformation.Encryption = Decrypt(decryptedVerified, verified, key, true);

                    decryptedVerified.Position = 0; //reset the stream

                    result.UnsealedData = factory.CreateNew();
                    result.SecurityInformation.InnerSignature = Verify(result.UnsealedData, decryptedVerified, true, false);

                    result.UnsealedData.Position = 0; //reset the stream

                    return result;
                }
            }
        }

        private UnsealResult UnsealOptimized(ITempStreamFactory factory, Stream sealedData, SecretKey key)
        {
            overrideOrigine = null;
            overrideOrigineMutex.Reset();
            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();

            VerifyParams outer;
            DecryptParams decrypt;
            VerifyParams inner;

            //Create pipe pair for outer signed stream
            Stream verified = new MemoryPipeStream();
            try
            {
                //Verify outer signature
                outer = new VerifyParams(verified, sealedData, true, false);
                outerSignatureThread.Start(outer);

                //Create pipe pair for decryption stream
                Stream decryptedVerified = new MemoryPipeStream();
                try
                {
                    //Decrypt
                    decrypt = new DecryptParams(decryptedVerified, verified, key, true);
                    decryptThread.Start(decrypt);

                    //This is the output, so we need to make it a temp stream (temp file or memory stream)
                    result.UnsealedData = factory.CreateNew();

                    //Verify inner signature
                    inner = new VerifyParams(result.UnsealedData, decryptedVerified, true, true);
                    innerSignatureThread.Start(inner);

                    //Wait to outer verification to finish & close source
                    outerSignatureThread.Join();
                    verified.Close();
                    verified = null;

                    //Wait to decryption to finish & close source
                    decryptThread.Join();
                    decryptedVerified.Close();
                    decryptedVerified = null;

                    //Wait to inner verification to finish
                    innerSignatureThread.Join();
                }
                finally
                {
                    if (decryptedVerified != null) decryptedVerified.Close();
                }
            }
            finally
            {
                if (verified != null) verified.Close();
            }

            //Check results
            if (outer != null && outer.exception == null)
            {
                result.SecurityInformation.OuterSignature = outer.result;
            }
            else
            {
                Rethrow(outer.exception, "Failed to validate outer signature");
            }
            if (decrypt != null && decrypt.exception == null)
            {
                result.SecurityInformation.Encryption = decrypt.result;
            }
            else
            {
                Rethrow(decrypt.exception, "Failed to decrypt the message");
            }
            if (inner != null && inner.exception == null)
            {
                result.SecurityInformation.InnerSignature = inner.result;
            }
            else
            {
                Rethrow(inner.exception, "Failed to validate inner signature");
            }

            result.UnsealedData.Position = 0; //reset the stream

            return result;
        }

        private static void Rethrow(Exception e, String msg)
        {
            if (e is InvalidMessageException)
            {
                throw new InvalidMessageException(e.Message, e);
            }
            else if (e is InvalidOperationException)
            {
                throw new InvalidOperationException(e.Message, e);
            }
            else if (e is NotSupportedException)
            {
                throw new NotSupportedException(e.Message, e);
            }
            else
            {
                throw new InvalidOperationException(msg, e);
            }
        }
        

        private UnsealResult Unseal(ITempStreamFactory factory, Stream sealedData, SecretKey key)
        {
            overrideOrigine = null;
            UnsealResult result = new UnsealResult();
            result.SecurityInformation = new UnsealSecurityInformation();

            Stream verified = factory.CreateNew();
            using(verified)
            {
                result.SecurityInformation.OuterSignature = Verify(verified, sealedData, false, false);
                overrideOrigine = result.SecurityInformation.OuterSignature.Subject;
                //trace.TraceEvent(TraceEventType.Information, 0, "Verified the outer signature");

                verified.Position = 0; //reset the stream

                Stream decryptedVerified = factory.CreateNew();
                using (decryptedVerified)
                {
                    result.SecurityInformation.Encryption = Decrypt(decryptedVerified, verified, key, false);
                    //trace.TraceEvent(TraceEventType.Information, 0, "Decrypted the message");

                    decryptedVerified.Position = 0; //reset the stream

                    result.UnsealedData = factory.CreateNew();
                    result.SecurityInformation.InnerSignature = Verify(result.UnsealedData, decryptedVerified, false, false);
                    //trace.TraceEvent(TraceEventType.Information, 0, "Verified the inner signature, finished");

                    result.UnsealedData.Position = 0; //reset the stream

                    return result;
                }
            }
        }

        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void Verify(Object data)
        {
            VerifyParams param = (VerifyParams)data;
            try
            {
                param.result = Verify(param.verifiedContent, param.signed, param.optimized, param.wait);
                overrideOrigine = param.result.Subject;
                overrideOrigineMutex.Set();
            }
            catch (Exception e)
            {
                overrideOrigineMutex.Set();
                param.exception = e;
            }
        }
        

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA1801:ReviewUnusedParameters", MessageId = "wait")]
        private SecurityInformation Verify(Stream verifiedContent, Stream signed, bool optimize, bool wait)
        {
            try
            {
                Object signedData;
                try
                {
                    if (optimize)
                    {
                        signedData = new CmsSignedDataParser(signed);
                    }
                    else
                    {
                        signedData = new CmsSignedData(signed);
                    }
                }
                catch (Exception e)
                {
                    throw new InvalidMessageException("The message isn't a tripple wrapped message", e);
                }
                if (optimize)
                {
                    CmsSignedDataParser signedParser = (CmsSignedDataParser) signedData;
                    StreamUtils.Copy(signedParser.GetSignedContent().ContentStream, verifiedContent);
                    if (wait) overrideOrigineMutex.WaitOne(); //wait until we get the override
                    return Verifier.Verify(signedParser, overrideOrigine);
                }
                else
                {
                    CmsSignedData signedParsed = (CmsSignedData) signedData;
                    StreamUtils.Copy(signedParsed.SignedContent.Read(), verifiedContent);
                    return Verifier.Verify(signedParsed, overrideOrigine);
                }
            }
            catch(CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

        
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void Decrypt(Object data)
        {
            DecryptParams param = (DecryptParams)data;
            try
            {
                param.result = Decrypt(param.clear, param.cypher, param.key, param.optimized);
            }
            catch (Exception e)
            {
                param.exception = e;
            }
        }
        


        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Maintainability", "CA1506:AvoidExcessiveClassCoupling")]
        private SecurityInformation Decrypt(Stream clear, Stream cypher, SecretKey key, bool optimize)
        {
            try
            {
                SecurityInformation result = new SecurityInformation();
                Object cypherData;
                try
                {
                    if (optimize)
                    {
                        cypherData = new CmsEnvelopedDataParser(cypher);
                    }
                    else
                    {
                        cypherData = new CmsEnvelopedData(cypher);
                    }
                }
                catch (Exception e)
                {
                    throw new InvalidMessageException("The message isn't a tripple wrapped message", e);
                }
                RecipientInformationStore recipientInfos = optimize ? ((CmsEnvelopedDataParser) cypherData).GetRecipientInfos() : ((CmsEnvelopedData) cypherData).GetRecipientInfos();

                if ((optimize ? ((CmsEnvelopedDataParser)cypherData).EncryptionAlgOid : ((CmsEnvelopedData)cypherData).EncryptionAlgOid) != EteeActiveConfig.Unseal.EncryptionAlgorithm.Value) result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionAlgorithm);
                //EXTEND: check key size of message

                //Get recipient, should be receiver.
                RecipientInformation recipientInfo;
                ICipherParameters recipientKey;
                if (key == null)
                {
                    if (enc != null)
                    {
                        //Get receiver
                        BC::X509Certificate bcEnc = DotNetUtilities.FromX509Certificate(enc);
                        RecipientID recipientId = new RecipientID();
                        recipientId.SerialNumber = bcEnc.SerialNumber;
                        recipientId.Issuer = bcEnc.IssuerDN;
                        recipientInfo = recipientInfos.GetFirstRecipient(recipientId);
                        if (recipientInfo == null) throw new InvalidMessageException("The message isn't a message that is addressed to you.  Or it is an unaddressed message or it is addressed to somebody else");

                        //Validate receiver (=zelf) using standard validation tools
                        result.Subject = Verifier.Verify(bcEnc, DotNetUtilities.FromX509Certificate(auth));

                        //Get receiver key
                        recipientKey = DotNetUtilities.GetKeyPair(enc.PrivateKey).Private;
                    }
                    else
                    {
                        throw new InvalidOperationException("There should be an receiver (=yourself) and/or a key provided");
                    }
                }
                else
                {
                    RecipientID recipientId = new RecipientID();
                    recipientId.KeyIdentifier = key.Id;
                    recipientInfo = recipientInfos.GetFirstRecipient(recipientId);
                    if (recipientInfo == null) throw new InvalidMessageException("The key isn't for this unaddressed message");
                    recipientKey = key.BCKey;

                    //Validate the unaddressed key
                    if ((((KeyParameter)recipientKey).GetKey().Length * 8) < EteeActiveConfig.Unseal.MinimuumEncryptionKeySize.SymmetricRecipientKey) result.securityViolations.Add(SecurityViolation.NotAllowedEncryptionKeySize);
                }

                //check if key encryption algorithm is allowed
                int i = 0;
                bool found = false;
                while (!found && i < EteeActiveConfig.Unseal.KeyEncryptionAlgorithms.Count)
                {
                    found = EteeActiveConfig.Unseal.KeyEncryptionAlgorithms[i++].Value == recipientInfo.KeyEncryptionAlgOid;
                }
                if (!found) result.securityViolations.Add(SecurityViolation.NotAllowedKeyEncryptionAlgorithm);

                //Decrypt!
                CmsTypedStream clearStream = recipientInfo.GetContentStream(recipientKey);
                StreamUtils.Copy(clearStream.ContentStream, clear);

                return result;
            }
            catch (CmsException cmse)
            {
                throw new InvalidMessageException("The message isn't a tripple wrapped message", cmse);
            }
        }

    }
}
