using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Sts.WsTrust200512
{
    [ServiceContract(Namespace = "urn:be:fgov:ehealth:sts:protocol:v1")]
    public interface IWsTrustPortFixed
    {

        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", ReplyAction = "*")]
        [XmlSerializerFormat(SupportFaults = true)]
        [ServiceKnownType(typeof(EncryptedType))]
        Message RequestSecurityToken(RequestSecurityTokenRequest request);

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
    public class WsTrustClient : ClientBase<IWsTrustPortFixed>, IStsClient
    {
        private static readonly Regex ClaimTypeExp = new Regex("({(?<ns>.+)})?(?<name>.+)", RegexOptions.Compiled);

        private readonly ILogger _logger;

        public WsTrustClient(ILogger<WsTrustClient> logger = null)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(ServiceEndpoint endpoint, ILogger<WsTrustClient> logger = null) :
            base(endpoint)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public WsTrustClient(Binding binding, EndpointAddress remoteAddress, ILogger<WsTrustClient> logger = null) :
            base(binding, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        public XmlElement RenewTicket(X509Certificate2 sessionCert, XmlElement previousTicket)
        {
            //make the request
            var request = new RequestSecurityTokenRequest()
            {
                RequestSecurityToken = new RequestSecurityTokenType()
                {
                    Context = "urn:uuid:" + Guid.NewGuid().ToString(),
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
                    RequestType = RequestTypeEnum.httpdocsoasisopenorgwssxwstrust200512Renew,
                    RenewTarget = new RenewTargetType()
                    {
                        SecurityTokenReference = new SecurityTokenReferenceType()
                        {
                            Embedded = new EmbeddedType()
                            {
                                Any = previousTicket
                            }
                        }
                    }
                }
            };

            return Send(sessionCert, request);
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, IList<Claim> assertingClaims, IList<Claim> additinalClaims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(sessionCert, notBefore, notBefore.Add(duration), assertingClaims, additinalClaims);
        }

        public XmlElement RequestTicket(X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, IList<Claim> assertingClaims, IList<Claim> additinalClaims)
        {
            var useKey = sessionCert == null ? null : new UseKeyType
            {
                SecurityTokenReference = new SecurityTokenReferenceType()
                {
                    X509Data = new X509DataType()
                    {
                        ItemsElementName = new ItemsChoiceType[] { ItemsChoiceType.X509Certificate },
                        Items = new object[] { sessionCert.Export(X509ContentType.Cert) }
                    }
                }
            };

            //make the request
            var request = new RequestSecurityTokenRequest()
            {
                RequestSecurityToken = new RequestSecurityTokenType()
                {
                    Context = "urn:uuid:" + Guid.NewGuid().ToString(),
                    TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1",
                    RequestType = RequestTypeEnum.httpdocsoasisopenorgwssxwstrust200512Issue,
                    Claims = new ClaimsType()
                    {
                        Dialect = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims",
                        ClaimType = Enumerable.Union(
                            assertingClaims.Select(c => new ClaimType()
                            {
                                Uri = ClaimTypeExp.Match(c.Type).Groups["name"].Value,
                                Item = c.Value
                            }),
                            additinalClaims.Select(c => new ClaimType()
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
                    UseKey = useKey
                }
            };

            //send it
            return Send(sessionCert, request);
        }

        private XmlElement Send(X509Certificate2 sessionCert, RequestSecurityTokenRequest request)
        {
            Message responseMsg = base.Channel.RequestSecurityToken(request);
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 10240), responseMsg.Headers.Action);
            }
            var responseBody = new XmlDocument();
            responseBody.PreserveWhitespace = true;
            responseBody.Load(responseMsg.GetReaderAtBodyContents());

            XmlNodeList assertions = responseBody.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:1.0:assertion");
            if (assertions.Count == 1)
            {
                //TODO::check if proper parent
                return (XmlElement)assertions[0];
            }
            else
            {
                var serializer = new XmlSerializer(typeof(RequestSecurityTokenResponseType), new XmlRootAttribute("RequestSecurityTokenResponse")
                {
                    Namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                });
                var reader = new XmlNodeReader(responseBody);
                var responseObject = (RequestSecurityTokenResponseType)serializer.Deserialize(reader);
                return ProcessChallenge(sessionCert, responseObject);
            }
        }


        private XmlElement ProcessChallenge(X509Certificate2 sessionCert, RequestSecurityTokenResponseType response)
        {
            //we expect SignChallenge, which we need to return as SignChallengeResponse using the body cert/key.
            if (response.SignChallenge == null) throw new InvalidOperationException("eHealth WS-Trust service didn't return sign challenge response");
            response.SignChallengeResponse = response.SignChallenge;
            response.SignChallenge = null;

            //create a secondary channel with new credentails to send the challenge
            ChannelFactory<IWsTrustPortFixed> channelFactory = new ChannelFactory<IWsTrustPortFixed>(base.Endpoint.Binding, base.Endpoint.Address);
            channelFactory.Credentials.ClientCertificate.Certificate = sessionCert;
            IWsTrustPortFixed secondary = channelFactory.CreateChannel();

            //send the (signed) Challenge, get the reponse as message to not break the internal signature
            Message responseMsg = secondary.Challenge(new RequestSecurityTokenResponse()
            {
                RequestSecurityTokenResponse1 = response
            });

            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 10240), responseMsg.Headers.Action);
            }

            var responseBody = new XmlDocument();
            responseBody.PreserveWhitespace = true;
            responseBody.Load(responseMsg.GetReaderAtBodyContents());

            //TODO::check if correcty wrapped, but for now we do not care.
            return (XmlElement)responseBody.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:1.0:assertion")[0];
        }
    }
}