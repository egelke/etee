using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Encrypt;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.RegularExpressions;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.Xml;
using Siemens.EHealth.Etee.Crypto.Library.Xsd.V1;
using System.Xml.Serialization;

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public abstract class PostMaster : INotifyPropertyChanged
    {
        private static EncryptionToken kgssToken;

        public static EncryptionToken KgssToken
        {
            get
            {
                return kgssToken;
            }
            set
            {
                kgssToken = value;
            }
        }

        private bool lax = true;

        public bool Lax
        {
            get { return lax; }
            set { lax = value; }
        }

        private bool verifyEtk = true;

        public bool VerifyEtk
        {
            get { return verifyEtk; }
            set { verifyEtk = value; }
        }

        private IDataSealer sealer;

        private IAnonymousDataUnsealer anonUnsealer = DataUnsealerFactory.Create();

        private IDataUnsealer unsealer;

        private SecurityInfo self;

        private ServiceClient.EtkDepotPortTypeClient etkDepot;

        public ServiceClient.EtkDepotPortTypeClient EtkDepotClient
        {
            get { return etkDepot; }
            set { etkDepot = value; }
        }

        private ServiceClient.KgssPortTypeClient kgss;

        public ServiceClient.KgssPortTypeClient KgssClient
        {
            get { return kgss; }
            set { kgss = value; }
        }

        /// <summary>
        /// To receive addressed messages only.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="etkDepot"></param>
        public PostMaster(SecurityInfo self)
            : this(self, null, null)
        {

        }

        /// <summary>
        /// To send/receive addressed messages only.
        /// </summary>
        /// <param name="self">Identification of user, can be used with send-only instance.</param>
        /// <param name="etkDepot"></param>
        public PostMaster(SecurityInfo self,  ServiceClient.EtkDepotPortTypeClient etkDepot)
            : this(self, etkDepot, null)
        {

        }

        /// <summary>
        /// For all purposes.
        /// </summary>
        /// <param name="self"></param>
        /// <param name="etkDepot"></param>
        /// <param name="kgss"></param>
        public PostMaster(SecurityInfo self, ServiceClient.EtkDepotPortTypeClient etkDepot, ServiceClient.KgssPortTypeClient kgss)
        {
            this.Self = self;
            this.etkDepot = etkDepot;
            this.kgss = kgss;
        }

        public SecurityInfo Self
        {
            get
            {
                return self;
            }
            set
            {
                self = value;
                if (self != null)
                {
                    sealer = DataSealerFactory.Create(self.AuthenticationCertificate);
                    if (self.EncryptionCertificate != null)
                    {
                        unsealer = DataUnsealerFactory.Create(self.EncryptionCertificate, self.AuthenticationCertificate);
                    }
                    else
                    {
                        unsealer = null;
                    }
                }
                else
                {
                    sealer = null;
                    unsealer = null;
                }
                OnPropertyChanged(new PropertyChangedEventArgs("Sender"));
            }
        }

        /// <summary>
        /// Encryptes the request, send it, receives the unencrypted response and return its.
        /// </summary>
        /// <param name="toEncrypt">The clear text message to encrypt</param>
        /// <param name="parameters">Additional information that is required to send the message but that will not be encrypted</param>
        /// <param name="recipients">Special paremeter: used by the postmaster for the encrypted, but may also be used to send the message</param>
        /// <returns>The unencrypted response, which can be null</returns>
        public Object TransferAndEncryptOnly(Stream toEncrypt, Object parameters, ReadOnlyCollection<Recipient> recipients)
        {
            X509Certificate2 sender;
            return TransferAndDoCrypto(toEncrypt, parameters, recipients, out sender).Item2;
        }

        /// <summary>
        /// Send the unencrypted request, receives the encrypted response, decryptes the response and returns it.
        /// </summary>
        /// <param name="parameters">Information that is required to send the message</param>
        /// <param name="sender">Contains the certificate of the sender of the response</param>
        /// <returns>Returns the decrypted stream and the non encrypted information returned (null if no uncrypted information is provided)</returns>
        public Tuple<Stream, Object> TransferAndDecryptOnly(Object parameters, out X509Certificate2 sender)
        {
            return TransferAndDoCrypto(null, parameters, null, out sender);
        }

        /// <summary>
        /// Encryptes the request, send it, receives the encrypted response, decryptes the response and return its.
        /// </summary>
        /// <param name="toEncrypt">The clear text message to encrypt, can be null if the request does not contain an encrypted part</param>
        /// <param name="parameters">Additional information that is required to send the message but that will not be encrypted</param>
        /// <param name="recipients">Special paremeter: used by the postmaster for the encrypted, but may also be used to send the message</param>
        /// <param name="sender">Contains the certificate of the sender of the response, is null when the response wasn't encrypted</param>
        /// <returns>Returns the decrypted stream (or null the response does not contain an encrypted part) and the non encrypted information returned (null if no uncrypted information is provided)</returns>
        public Tuple<Stream, Object> TransferAndDoCrypto(Stream toEncrypt, Object parameters, ReadOnlyCollection<Recipient> recipients, out X509Certificate2 sender)
        {
            byte[] keyId = null;
            Stream cypheredRequest = null;
            if (toEncrypt != null) 
            {
                if (recipients == null) throw new ArgumentNullException("recipients", "recipients is required when toEncrypte is provided");
                cypheredRequest = OnCrypt(toEncrypt, recipients, out keyId);
            }
            Tuple<Stream, Object> cypheredResponse = OnTransferEncrypted(cypheredRequest, parameters, ref keyId, recipients);

            Tuple<Stream, Object> clearResponse;
            if (cypheredResponse.Item1 != null)
            {
                clearResponse = new Tuple<Stream,object>(OnDecrypt(cypheredResponse.Item1, keyId, out sender), cypheredResponse.Item2);
            }
            else
            {
                sender = null;
                clearResponse = cypheredResponse;
            }
            return clearResponse;
        }

        /// <summary>
        /// Override with the required protocol to send the provide encrypted request and receive the encrypted response.
        /// </summary>
        /// <remarks>
        /// <para>
        /// As input this method gets the encrypted request (part) and some additional parameters.  The first parameter is business specific and
        /// can be anything.  It is provided by the user of the library via the call to one of the transfer methods.  The second paramter, keyId,
        /// is generated by the postmaster, but can be required to be transfered.  The last paramter, recipients, is already used by the postmaster
        /// but can used again to for the transfer.
        /// </para>
        /// <para>
        /// The response consists of 2 parts, the encrypted stream and additional return information that isn't encrypted.  In case the response does
        /// not contain an encrypted part, this pert item will be null.
        /// </para>
        /// </remarks>
        /// <param name="encrypted">The encrypted message to send (null if request is not encrypted)</param>
        /// <param name="parameters">Any additional, non encrypted, information required to send the message (null if no uncrypted information is required)</param>
        /// <param name="keyId">Special parameter: The key id for anonymous encryption (null if no anonymous adressing or is request is not encrypted).
        /// Should be updated when the response also has a key-id present</param>
        /// <param name="recipients">Special parameter: The list of recipients to send the message too (null if receive only)</param>
        /// <returns>Returns the encrypted stream (or null if response is clear text) and non encrypted information returned (null if no uncrypted information is provided)</returns>
        protected abstract Tuple<Stream, Object> OnTransferEncrypted(Stream encrypted, Object parameters, ref byte[] keyId, ReadOnlyCollection<Recipient> recipients);

        protected virtual Stream OnDecrypt(Stream cryphered, byte[] keyId, out X509Certificate2 sender)
        {
            UnsealResult result;
            if (keyId == null || kgss == null)
            {
                if (unsealer == null) throw new InvalidOperationException("Unsealer is required");

                result = unsealer.Unseal(cryphered);
            } else {
                SecretKey kek = GetKek(keyId);
                result = anonUnsealer.Unseal(cryphered, kek);
            }
            CheckResult(result.SecurityInformation);
            sender = result.Sender;
            return result.UnsealedData;
        }

        /// <summary>
        /// Addresses a files to a list of recipients (=make sure only those persons can read the file) and writes the result.
        /// </summary>
        /// <param name="clear"></param>
        /// <param name="recipients">The list of recipients.  Warning: when the funtion returns, the etk-propeties may be</param>
        /// <param name="cyphered"></param>
        /// <returns>The anonymous key in case there are unaddressed recipients</returns>
        protected virtual Stream OnCrypt(Stream clear, ReadOnlyCollection<Recipient> recipients, out byte[] keyId)
        {
            if (sealer == null) throw new InvalidOperationException("Sealer is required");

            SecretKey kek = null;
            IList<EncryptionToken> etks = new List<EncryptionToken>();

            IEnumerable<KnownRecipient> knownRecipients = from r in recipients
                                                          where r is KnownRecipient
                                                          select (KnownRecipient)r;
            foreach (KnownRecipient knownRecipient in knownRecipients)
            {
                etks.Add(GetToken(knownRecipient));
            }

            IEnumerable<UnknownRecipient> unknownRecipients = from r in recipients
                                                          where r is UnknownRecipient
                                                          select (UnknownRecipient)r;
            if (unknownRecipients.Count<UnknownRecipient>() > 0)
            {
                kek = GetKek(unknownRecipients);
                keyId = kek.Id;
            }
            else
            {
                keyId = null;
            }

            return sealer.Seal(new ReadOnlyCollection<EncryptionToken>(etks), clear, kek);
        }

        private void UpdateKgssToken()
        {
            bool lookup;
            ServiceClient.GetEtkRequest etkRequest;
            ServiceClient.GetEtkResponse etkResponse;

            lookup = KgssToken == null;
            if (!lookup)
            {
                //check if we don't need to override the lookup
                try
                {
                    Verify(KgssToken);
                }
                catch (VerifyException<EtkSecurityViolation>)
                {
                    lookup = true;
                }
            }
            if (lookup)
            {
                etkRequest = new ServiceClient.GetEtkRequest();
                etkRequest.SearchCriteria = new ServiceClient.IdentifierType[1];
                etkRequest.SearchCriteria[0] = new ServiceClient.IdentifierType();
                etkRequest.SearchCriteria[0].Type = "CBE";
                etkRequest.SearchCriteria[0].Value = "0809394427";
                etkRequest.SearchCriteria[0].ApplicationID = "KGSS";

                etkResponse = etkDepot.GetEtk(etkRequest);
                ServiceException.Check(etkResponse);

                byte[] kgssEtkRaw = null;
                foreach (Object item in etkResponse.Items)
                {
                    if (item is ServiceClient.MatchingEtk)
                    {
                        throw new InvalidOperationException("Token could not be retrieved, none/multiple tokens match");
                    }
                    else if (item is byte[])
                    {
                        kgssEtkRaw = (byte[])item;
                    }
                }
                KgssToken = new EncryptionToken(kgssEtkRaw);
                Verify(KgssToken);
            }
        }

        private void UpdateSelfToken()
        {
            bool lookup;
            ServiceClient.GetEtkRequest etkRequest;
            ServiceClient.GetEtkResponse etkResponse;

            lookup = self.Token == null;
            if (!lookup)
            {
                //check if we don't need to override the lookup
                try
                {
                    Verify(self.Token);
                }
                catch (VerifyException<EtkSecurityViolation>)
                {
                    lookup = true;
                }
            }
            if (lookup)
            {
                Regex regex = new Regex("CN=[\"](?<type>.*)=(?<id>.*)[\"]");
                MatchCollection matches = regex.Matches(self.AuthenticationCertificate.Subject);

                etkRequest = new ServiceClient.GetEtkRequest();
                etkRequest.SearchCriteria = new ServiceClient.IdentifierType[1];
                etkRequest.SearchCriteria[0] = new ServiceClient.IdentifierType();
                etkRequest.SearchCriteria[0].Type = matches[0].Groups["type"].Value;
                etkRequest.SearchCriteria[0].Value = matches[0].Groups["id"].Value;

#if DEBUG
                //Translate old Alice & Bob NIHII numbers into new onces
                if (etkRequest.SearchCriteria[0].Value == "00000000101") etkRequest.SearchCriteria[0].Value = "00000196101";
                if (etkRequest.SearchCriteria[0].Value == "00000000202") etkRequest.SearchCriteria[0].Value = "00000295202";
#endif

                etkResponse = etkDepot.GetEtk(etkRequest);
                ServiceException.Check(etkResponse);

                byte[] ownEtkRaw = null;
                foreach (Object item in etkResponse.Items)
                {
                    if (item is ServiceClient.MatchingEtk)
                    {
                        throw new InvalidOperationException("Token could not be retrieved, none/multiple tokens match");
                    }
                    else if (item is byte[])
                    {
                        ownEtkRaw = (byte[])item;
                    }
                }
                self.Token = new EncryptionToken(ownEtkRaw);
                Verify(self.Token);
            }
        }

        virtual protected SecretKey GetKek(byte[] keyId)
        {
            if (sealer == null) throw new InvalidOperationException("Sealer is required");
            if (unsealer == null) throw new InvalidOperationException("Unsealer is required");

            //Get required info.
            UpdateSelfToken();
            UpdateKgssToken();

            //Create request content
            GetKeyRequestContent requestContent = new GetKeyRequestContent();
            requestContent.KeyIdentifier = keyId;
            requestContent.ETK = (byte[])self.Token.GetEncoded();
            XmlSerializer serializer = new XmlSerializer(typeof(GetKeyRequestContent));
            MemoryStream buffer = new MemoryStream();
            serializer.Serialize(buffer, requestContent);

            //Encrypt request content
            byte[] sealedRequestContent = sealer.Seal(KgssToken, buffer.ToArray());

            //Get response
            ServiceClient.GetKeyRequest request = new ServiceClient.GetKeyRequest();
            request.SealedKeyRequest = new ServiceClient.SealedContentType();
            request.SealedKeyRequest.SealedContent = sealedRequestContent;
            ServiceClient.GetKeyResponse response = kgss.GetKey(request);
            ServiceException.Check(response);

            //Decrypt the reponse
            UnsealResult key = unsealer.Unseal(new MemoryStream(response.SealedKeyResponse.SealedContent));
            CheckResult(key.SecurityInformation);

            //Process the response
            serializer = new XmlSerializer(typeof(GetKeyResponseContent));
            GetKeyResponseContent keyReponse = (GetKeyResponseContent)serializer.Deserialize(key.UnsealedData);

            return new SecretKey(keyId, keyReponse.Key);
        }

        private SecretKey GetKek(IEnumerable<UnknownRecipient> unknownRecipients)
        {
            if (sealer == null) throw new InvalidOperationException("Sealer is required");
            if (unsealer == null) throw new InvalidOperationException("Unsealer is required");

            //Get required info.
            UpdateSelfToken();
            UpdateKgssToken();

            Dictionary<String, CredentialType> dic = new Dictionary<string, CredentialType>();
            GetNewKeyRequestContent requestContent = new GetNewKeyRequestContent();
            foreach (UnknownRecipient recipient in unknownRecipients)
            {
                CredentialType cred;
                if (!dic.TryGetValue(recipient.Namespace + "#" + recipient.Name, out cred))
                {
                    cred = new CredentialType();
                    cred.Namespace = recipient.Namespace;
                    cred.Name = recipient.Name;
                    dic.Add(recipient.Namespace + "#" + recipient.Name, cred);
                }
                if (!String.IsNullOrWhiteSpace(recipient.Value))
                {
                    if (cred.Value == null) cred.Value = new List<string>();
                    cred.Value.Add(recipient.Value);
                }
            }
            foreach (CredentialType cred in dic.Values)
            {
                if (requestContent.AllowedReader == null) requestContent.AllowedReader = new List<CredentialType>();
                requestContent.AllowedReader.Add(cred);
            }
            requestContent.ETK = self.Token.GetEncoded();

            MemoryStream clearKgssContent = new MemoryStream();
            XmlSerializer serializer = new XmlSerializer(typeof(GetNewKeyRequestContent));
            serializer.Serialize(clearKgssContent, requestContent);


            ServiceClient.GetNewKeyRequest keyRequest = new ServiceClient.GetNewKeyRequest();
            keyRequest.SealedNewKeyRequest = new ServiceClient.SealedContentType();
            keyRequest.SealedNewKeyRequest.SealedContent = sealer.Seal(KgssToken, clearKgssContent.ToArray());

            ServiceClient.GetNewKeyResponse keyResponse = kgss.GetNewKey(keyRequest);
            ServiceException.Check(keyResponse);

            MemoryStream enckey = new MemoryStream(keyResponse.SealedNewKeyResponse.SealedContent);
            UnsealResult rawKey = unsealer.Unseal(enckey);

            serializer = new XmlSerializer(typeof(GetNewKeyResponseContent));
            GetNewKeyResponseContent responseContent = (GetNewKeyResponseContent)serializer.Deserialize(rawKey.UnsealedData);

            return new SecretKey(responseContent.NewKeyIdentifier, responseContent.NewKey);
        }

        private EncryptionToken GetToken(KnownRecipient knownRecipient)
        {
            bool lookup = knownRecipient.Token == null;
            if (!lookup)
            {
                //check if we don't need to override the lookup
                try
                {
                    Verify(knownRecipient.Token);
                }
                catch (VerifyException<EtkSecurityViolation>)
                {
                    lookup = true;
                }
            }
            if (lookup)
            {
                ServiceClient.GetEtkRequest request = new ServiceClient.GetEtkRequest();
                request.SearchCriteria = new ServiceClient.IdentifierType[1];
                request.SearchCriteria[0] = new ServiceClient.IdentifierType();
                request.SearchCriteria[0].Type = knownRecipient.Type;
                request.SearchCriteria[0].Value = knownRecipient.Id;
                request.SearchCriteria[0].ApplicationID = knownRecipient.Application;

                ServiceClient.GetEtkResponse response = etkDepot.GetEtk(request);
                ServiceException.Check(response);

                byte[] etkRaw = null;
                foreach (Object item in response.Items)
                {
                    if (item is ServiceClient.MatchingEtk)
                    {
                        throw new InvalidOperationException("The token could not be retrieved, none/multiple tokens match");
                    }
                    else if (item is byte[])
                    {
                        etkRaw = (byte[])item;
                    }
                }
                knownRecipient.Token = new EncryptionToken(etkRaw);
                if (verifyEtk) Verify(knownRecipient.Token);
            }
            return knownRecipient.Token;
        }

        private void Verify(EncryptionToken token)
        {
            CheckResult(token.Verify());
        }

        private void CheckResult<Violation>(SecurityResult<Violation> info)
            where Violation : struct, IConvertible
        {
            if ((info.ValidationStatus == ValidationStatus.Valid || (lax && info.ValidationStatus == ValidationStatus.Unsure))
                && (info.TrustStatus == Decrypt.TrustStatus.Full || (lax && info.TrustStatus == Decrypt.TrustStatus.Unsure)))
            {
                //OK, possible logging here
            }
            else
            {
                throw new VerifyException<Violation>(info);
            }
        }

        protected virtual void OnPropertyChanged(PropertyChangedEventArgs e)
        {
            if (PropertyChanged != null)
            {
                PropertyChanged.Invoke(this, e);
            }
        }

        #region INotifyPropertyChanged Members

        public event PropertyChangedEventHandler PropertyChanged;

        #endregion
    }
}
