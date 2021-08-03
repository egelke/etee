using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Egelke.EHealth.Client.Sts.WsTrust200512
{
    [ServiceContract(Namespace = "urn:be:fgov:ehealth:sts:protocol:v1")]
    internal interface IWsTrustPortFixed
    {

        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", ReplyAction = "*")]
        [XmlSerializerFormat(SupportFaults = true)]
        [ServiceKnownType(typeof(EncryptedType))]
        RequestSecurityTokenResponse RequestSecurityToken(RequestSecurityTokenRequest request);

        /*
        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", ReplyAction = "*")]
        System.Threading.Tasks.Task<Egelke.EHealth.Client.Sts.WsTrust200512.RequestSecurityTokenResponse> RequestSecurityTokenAsync(Egelke.EHealth.Client.Sts.WsTrust200512.RequestSecurityTokenRequest request);
        */

        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:Challenge", ReplyAction = "*")]
        [XmlSerializerFormat(SupportFaults = true)]
        [ServiceKnownType(typeof(EncryptedType))]
        Message Challenge(RequestSecurityTokenResponse request);

        /*
        [System.ServiceModel.OperationContractAttribute(Action = "urn:be:fgov:ehealth:sts:protocol:v1:Challenge", ReplyAction = "*")]
        System.Threading.Tasks.Task<Egelke.EHealth.Client.Sts.WsTrust200512.RequestSecurityTokenResponse> ChallengeAsync(Egelke.EHealth.Client.Sts.WsTrust200512.RequestSecurityTokenResponse request);
        */
    }
    public class WsTrustClient : ClientBase<SecurityTokenServicePort>, IStsClient
    {
        private static readonly Regex ClaimTypeExp = new Regex("({(?<ns>.+)})?(?<name>.+)", RegexOptions.Compiled);

        private readonly ILogger _logger;

        public WsTrustClient(ILogger<WsTrustClient> logger = null)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(string endpointConfigurationName, ILogger<WsTrustClient> logger = null) :
            base(endpointConfigurationName)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(string endpointConfigurationName, string remoteAddress, ILogger<WsTrustClient> logger = null) :
            base(endpointConfigurationName, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(string endpointConfigurationName, EndpointAddress remoteAddress, ILogger<WsTrustClient> logger = null) :
            base(endpointConfigurationName, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(Binding binding, EndpointAddress remoteAddress, ILogger<WsTrustClient> logger = null) :
            base(binding, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, IList<Claim> assertingClaims, IList<Claim> requestedClaims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(sessionCert, notBefore, notBefore.Add(duration), assertingClaims, requestedClaims);
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, IList<Claim> assertingClaims, IList<Claim> requestedClaims)
        {
            //make the request
            var request = new RequestSecurityTokenRequest()
            {
                RequestSecurityToken = new RequestSecurityTokenType()
                {
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
                    RequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
                    Claims = new ClaimsType()
                    {
                        Dialect = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims",
                        ClaimType = Enumerable.Union(
                            assertingClaims.Select(c => new ClaimType()
                            {
                                Uri = ClaimTypeExp.Match(c.Type).Groups["name"].Value,
                                Item = c.Value
                            }),
                            requestedClaims.Select(c => new ClaimType()
                            {
                                Uri = ClaimTypeExp.Match(c.Type).Groups["name"].Value
                            })
                            ).ToArray()
                    },
                    Lifetime = new LifetimeType()
                    {
                        Created = new AttributedDateTime()
                        {
                            Value = notBefore.ToString("O")
                        },
                        Expires = new AttributedDateTime()
                        {
                            Value = notOnOrAfter.ToString("O")
                        }
                    },
                    KeyType = "http://docs.oasis-open.org/ws-sx/wstrust/200512/PublicKey",
                    UseKey = new UseKeyType()
                    {
                        SecurityTokenReference = new SecurityTokenReferenceType()
                        {
                            X509Data = new X509DataType()
                            {
                                ItemsElementName = new ItemsChoiceType[] { ItemsChoiceType.X509Certificate },
                                Items = new object[] { sessionCert.Export(X509ContentType.Cert) }
                            }   
                        }
                    }
                }
            };

            //send it
            RequestSecurityTokenResponse response = base.Channel.RequestSecurityToken(request);

            //we expect SignChallenge, which we need to return as SignChallengeResponse using the body cert/key.
            if (response.RequestSecurityTokenResponse1.SignChallenge == null) throw new InvalidOperationException("eHealth WS-Trust service didn't return sign challenge response");
            response.RequestSecurityTokenResponse1.SignChallengeResponse = response.RequestSecurityTokenResponse1.SignChallenge;
            response.RequestSecurityTokenResponse1.SignChallenge = null;

            //create a secondary channel to send the challenge
            ChannelFactory<IWsTrustPortFixed> channelFactory = new ChannelFactory<IWsTrustPortFixed>(base.Endpoint.Binding, base.Endpoint.Address);
            channelFactory.Credentials.ClientCertificate.Certificate = sessionCert;
            IWsTrustPortFixed secondary = channelFactory.CreateChannel();
 
            //send the (signed) Challenge, get the reponse as message to not break the internal signature
            Message responseMsg = secondary.Challenge(response);

            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 10240), responseMsg.Headers.Action);
            }
            var responseBody = new XmlDocument();
            responseBody.PreserveWhitespace = true;
            responseBody.Load(responseMsg.GetReaderAtBodyContents());

            //better to check if correcty wrapped, but for now we do not care.

            return (XmlElement) responseBody.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:1.0:assertion")[0];
        }
    }
}