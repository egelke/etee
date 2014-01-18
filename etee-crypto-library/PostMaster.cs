using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Etee.Crypto.Encrypt;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.RegularExpressions;
using Egelke.EHealth.Etee.Crypto.Decrypt;
using System.Xml;
using Egelke.EHealth.Etee.Crypto.Library.Xsd.V1;
using System.Xml.Serialization;
using Egelke.EHealth.Etee.Crypto.Status;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Library
{
    public class PostMaster
    {
        private readonly static Regex eHCertSubject = new Regex("CN=[\"](?<type>.*)=(?<id>\\d*)(, (?<app>\\w+))?[\"]");

        private EncryptionToken kgssToken;

        private DateTime kgssTokenLastUpdate = DateTime.MinValue;

        private EncryptionToken KgssToken {
            get
            {
                //update the KGSS token regulary
                if (kgssTokenLastUpdate < (DateTime.UtcNow - EtkRenewalTime))
                {
                    kgssToken = GetToken(new KnownRecipient(new KnownRecipient.IdType("CBE", "0809394427"), "KGSS"));
                    kgssTokenLastUpdate = DateTime.UtcNow;
                }
                return kgssToken;
            }
        }

        public TimeSpan EtkRenewalTime { get; set; }

        public bool Test { get; set; }

        private bool probativeForce;

        public bool ProbativeForce
        {
            get
            {
                return probativeForce;
            }
            set
            {
                if (probativeForce != value)
                {
                    probativeForce= value;
                    anonUnsealer = DataUnsealerFactory.Create(probativeForce);
                    unsealer = DataUnsealerFactory.Create(probativeForce, DecryptionCertificates);
                }
            }
        }

        private IDataSealer kgssSealer;

        private IAnonymousDataUnsealer anonUnsealer;

        private IDataUnsealer unsealer;

        public X509Certificate2 AuthenticationCertificate { get; internal set; }

        private EncryptionToken ownToken;

        private DateTime ownTokenLastUpdate = DateTime.MinValue;

        public EncryptionToken OwnToken
        {
            get
            {
                if (kgssTokenLastUpdate < (DateTime.UtcNow - EtkRenewalTime))
                {
                    ownToken = GetToken(AuthenticationCertificate);
                }
                return ownToken;
            }
        }

        public X509Certificate2Collection DecryptionCertificates { get; internal set; }

        public ServiceClient.EtkDepotPortTypeClient EtkDepotClient { get; internal set; }

        public ServiceClient.KgssPortTypeClient KgssClient { get; internal set; }

        public ITransport Transport { get; internal set; }

        /// <summary>
        /// To send/receive addressed messages only.
        /// </summary>
        /// <param name="encCerts">The decryption certifciates, may be <c>null</c> or empty for send only</param>
        /// <param name="etkDepot"></param>
        public PostMaster(ITransport transport, X509Certificate2Collection decryptionCerts, ServiceClient.EtkDepotPortTypeClient etkDepot)
            : this(transport, null, decryptionCerts, etkDepot, null)
        {

        }

        /// <summary>
        /// To send/receive both addressed and unaddress messages.
        /// </summary>
        /// <param name="authCert">The certificate to sign the Kgss request, must be an eHealth certificate with matching decryption certificate</param>
        /// <param name="decryptionCerts">All decryption certificate, including the expired ones.  Must contain the decryption certificate that corresponds to the signgin certificate</param>
        public PostMaster(ITransport transport, X509Certificate2 authCert, X509Certificate2Collection decryptionCerts, ServiceClient.EtkDepotPortTypeClient etkDepot, ServiceClient.KgssPortTypeClient kgss)
        {
            //default values
            Test = false;
            probativeForce = false;

            if (transport == null) throw new ArgumentNullException("transport");
            this.Transport = transport;

            //Keep certs
            AuthenticationCertificate = authCert;
            DecryptionCertificates = decryptionCerts;

            //Init (un)sealers
            if (AuthenticationCertificate != null)
            {
                kgssSealer = DataSealerFactory.Create(AuthenticationCertificate);
                kgssSealer.Offline = true;
                anonUnsealer = DataUnsealerFactory.Create(probativeForce);
            }
            if (decryptionCerts != null & decryptionCerts.Count > 0)
            {
                unsealer = DataUnsealerFactory.Create(probativeForce, decryptionCerts);
            }

            //set clients
            this.EtkDepotClient = etkDepot;
            this.KgssClient = kgss;
        }


        /// <summary>
        /// Encryptes the request if confidential, send it, receives the response, decryptes it if confidential and return its.
        /// </summary>
        /// <param name="letter">The letter with the content to encrypt and additional info to send</param>
        /// <param name="isConfidential">Set to <c>true</c> if the request must be encrypted, otherwise <c>false</c></param>
        /// <param name="hasConfidentialResponse">Set to <c>true</c> if the response must be decrypted, othewise <c>false</c></param>
        /// <returns>The response with additional info, the contnet unecrypted if confidential (the content key id is never provided)</returns>
        /// <exception cref="ArgumentNullException">When on of the following parameters is <c>null</c>: letter</exception>
        public async Task<Letter> TransferAsync(Letter letter, bool isConfidential, bool hasConfidentialResponse)
        {
            if (letter == null && isConfidential) new ArgumentNullException("letter", "A letter is required in order to make it confidential");

            //Encrypt the letter, if needed
            Letter send = null;
            if (letter != null) {
                send = new Letter();
                send.Sender = letter.Sender;
                send.Headers = letter.Headers;
                if (isConfidential) 
                {
                    byte[] keyId = null;
                    if (letter.Recipients == null || letter.Recipients.Count == 0) throw new ArgumentNullException("recipients is required when toEncrypte is provided", "recipients");
                    send.Content = Crypt(letter.Sender, letter.Recipients, letter.Content, out keyId);
                    send.ContentKeyId = keyId;
                }
                else
                {
                    send.Content = letter.Content;
                }
            }

            //send the (encrypted) letter, receive a (encrypted) letter.
            Letter received = await Transport.TransferAsync(send);

            if (received == null && hasConfidentialResponse) throw new InvalidOperationException("The response confidential, but nothing was received");

            //decrypted the recieved letter if needed
            Letter returned = null;
            if (received != null)
            {
                returned = new Letter();
                returned.Headers = received.Headers;
                if (hasConfidentialResponse)
                {
                    X509Certificate2 sender;
                    returned.Content = Decrypt(received.Content, received.ContentKeyId, out sender);
                    returned.Sender = sender;
                    //TODO: extract the (named) recipients from the encrypted content.
                }
                else
                {
                    returned.Content = received.Content;
                    returned.Sender = received.Sender;
                    returned.Recipients = received.Recipients;
                }
            }

            return returned;
        }

        private Stream Decrypt(Stream cryphered, byte[] keyId, out X509Certificate2 other)
        {
            UnsealResult result;
            if (keyId == null || KgssClient == null)
            {
                if (unsealer == null) throw new InvalidOperationException("decryptionCerts is required");

                result = unsealer.Unseal(cryphered);
            } else {
                SecretKey kek = GetKek(keyId);
                result = anonUnsealer.Unseal(cryphered, kek);
            }
            CheckResult(result.SecurityInformation);
            other = result.Sender;
            return result.UnsealedData;
        }


        private Stream Crypt(X509Certificate2 sender, List<Recipient> recipients, Stream clear, out byte[] keyId)
        {
            if (sender == null) throw new ArgumentException("Sender is required");
            IDataSealer sealer = DataSealerFactory.Create(sender);

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
                kek = GetNewKek(unknownRecipients);
                keyId = kek.Id;
            }
            else
            {
                keyId = null;
            }

            return sealer.Seal(new ReadOnlyCollection<EncryptionToken>(etks), clear, kek);
        }

        private SecretKey GetKek(byte[] keyId)
        {
            if (kgssSealer == null) throw new InvalidOperationException("signingCert is required");
            if (unsealer == null) throw new InvalidOperationException("decryptionCerts is required");

            //Create request content
            GetKeyRequestContent requestContent = new GetKeyRequestContent();
            requestContent.KeyIdentifier = keyId;
            requestContent.ETK = OwnToken.GetEncoded();
            XmlSerializer serializer = new XmlSerializer(typeof(GetKeyRequestContent));
            MemoryStream buffer = new MemoryStream();
            serializer.Serialize(buffer, requestContent);

            //Encrypt request content
            byte[] sealedRequestContent = kgssSealer.Seal(KgssToken, buffer.ToArray());

            //Get response
            ServiceClient.GetKeyRequest request = new ServiceClient.GetKeyRequest();
            request.SealedKeyRequest = new ServiceClient.SealedContentType();
            request.SealedKeyRequest.SealedContent = sealedRequestContent;
            ServiceClient.GetKeyResponse response = KgssClient.GetKey(request);
            ServiceException.Check(response);

            //Decrypt the reponse
            UnsealResult key = unsealer.Unseal(new MemoryStream(response.SealedKeyResponse.SealedContent));
            CheckResult(key.SecurityInformation);

            //Process the response
            serializer = new XmlSerializer(typeof(GetKeyResponseContent));
            GetKeyResponseContent keyReponse = (GetKeyResponseContent)serializer.Deserialize(key.UnsealedData);

            return new SecretKey(keyId, keyReponse.Key);
        }

        private SecretKey GetNewKek(IEnumerable<UnknownRecipient> unknownRecipients)
        {
            if (kgssSealer == null) throw new InvalidOperationException("signingCert is required");
            if (unsealer == null) throw new InvalidOperationException("decryptionCerts is required");

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
            requestContent.ETK = OwnToken.GetEncoded();

            MemoryStream clearKgssContent = new MemoryStream();
            XmlSerializer serializer = new XmlSerializer(typeof(GetNewKeyRequestContent));
            serializer.Serialize(clearKgssContent, requestContent);


            ServiceClient.GetNewKeyRequest keyRequest = new ServiceClient.GetNewKeyRequest();
            keyRequest.SealedNewKeyRequest = new ServiceClient.SealedContentType();
            keyRequest.SealedNewKeyRequest.SealedContent = kgssSealer.Seal(KgssToken, clearKgssContent.ToArray());

            ServiceClient.GetNewKeyResponse keyResponse = KgssClient.GetNewKey(keyRequest);
            ServiceException.Check(keyResponse);

            MemoryStream enckey = new MemoryStream(keyResponse.SealedNewKeyResponse.SealedContent);
            UnsealResult rawKey = unsealer.Unseal(enckey);

            serializer = new XmlSerializer(typeof(GetNewKeyResponseContent));
            GetNewKeyResponseContent responseContent = (GetNewKeyResponseContent)serializer.Deserialize(rawKey.UnsealedData);

            return new SecretKey(responseContent.NewKeyIdentifier, responseContent.NewKey);
        }

        private EncryptionToken GetToken(X509Certificate2 certificate)
        {
            MatchCollection matches = eHCertSubject.Matches(certificate.Subject);
            if (matches.Count == 0) new ArgumentException("The authentication certificate must be from eHealth to use with KGSS (unaddresses encryption)");

            String id = matches[0].Groups["id"].Value;
#if DEBUG
            //Translate old Alice & Bob NIHII numbers into new onces
            switch (id)
            {
                case "00000000101":
                    id = "00000196101";
                    break;
                case "00000000202":
                    id = "00000295202";
                    break;
                default:
                    break;
            }
#endif
            String idType = matches[0].Groups["type"].Value;
            String application = matches[0].Groups["app"].Success ? matches[0].Groups["app"].Value : null;

            return RetrieveToken(new KnownRecipient(new KnownRecipient.IdType(idType, id), application));
        }

        private EncryptionToken GetToken(KnownRecipient knownRecipient)
        {
            if (knownRecipient.TokenRetreivalTime < (DateTime.UtcNow - EtkRenewalTime))
            {
                knownRecipient.Token = RetrieveToken(knownRecipient);
            }
            return knownRecipient.Token;
        }

        private EncryptionToken RetrieveToken(KnownRecipient knownRecipient)
        {
            ServiceClient.GetEtkRequest request = new ServiceClient.GetEtkRequest();
            request.SearchCriteria = new ServiceClient.IdentifierType[1];
            request.SearchCriteria[0] = new ServiceClient.IdentifierType();
            request.SearchCriteria[0].Type = knownRecipient.Id.Type;
            request.SearchCriteria[0].Value = knownRecipient.Id.Value;
            request.SearchCriteria[0].ApplicationID = knownRecipient.Application;

            ServiceClient.GetEtkResponse response = EtkDepotClient.GetEtk(request);
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
            var token = new EncryptionToken(etkRaw);
            //Verify(token);
            return token;
        }

        private void Verify(EncryptionToken token)
        {
            CheckResult(token.Verify());
        }

        private void CheckResult<Violation>(SecurityResult<Violation> info)
            where Violation : struct, IConvertible
        {
            if (info.ValidationStatus == ValidationStatus.Valid
                && (info.TrustStatus == Status.TrustStatus.Full || (Test && info.TrustStatus == Status.TrustStatus.Unsure)))
            {
                //OK, possible logging here
            }
            else
            {
                throw new VerifyException<Violation>(info);
            }
        }

    }
}
