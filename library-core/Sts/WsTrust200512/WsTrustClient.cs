/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
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
    /// <summary>
    /// WCF interface for WS-Trust of eHealth
    /// </summary>
    [ServiceContract(Namespace = "urn:be:fgov:ehealth:sts:protocol:v1")]
    public interface IWsTrustPortFixed
    {
        /// <summary>
        /// Request a new token
        /// </summary>
        /// <param name="request">request parameters</param>
        /// <returns>the obtained token or challange</returns>
        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:RequestSecurityToken", ReplyAction = "*")]
        [XmlSerializerFormat(SupportFaults = true)]
        [ServiceKnownType(typeof(EncryptedType))]
        Message RequestSecurityToken(RequestSecurityTokenRequest request);

        /// <summary>
        /// provide the Challenge for a HOK token.
        /// </summary>
        /// <param name="request">the request</param>
        /// <returns>the obtained token</returns>
        [OperationContract(Action = "urn:be:fgov:ehealth:sts:protocol:v1:Challenge", ReplyAction = "*")]
        [XmlSerializerFormat(SupportFaults = true)]
        [ServiceKnownType(typeof(EncryptedType))]
        Message Challenge(RequestSecurityTokenResponse request);


    }

    /// <summary>
    /// WCF client for WS-Trust of eHealth
    /// </summary>
    public class WsTrustClient : ClientBase<IWsTrustPortFixed>, IStsClient
    {
        private static readonly Regex ClaimTypeExp = new Regex("({(?<ns>.+)})?(?<name>.+)", RegexOptions.Compiled);

        private readonly ILogger _logger;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="logger">optional logger</param>
        public WsTrustClient(ILogger<WsTrustClient> logger = null)
            : base()
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        /// <summary>
        /// Constructor with custom endpoint
        /// </summary>
        /// <param name="endpoint">custom endpoint</param>
        /// <param name="logger">optional logger</param>
        public WsTrustClient(ServiceEndpoint endpoint, ILogger<WsTrustClient> logger = null) :
            base(endpoint)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        /// <summary>
        /// Constructor with custom binding and endpoint.
        /// </summary>
        /// <param name="binding">custom binding</param>
        /// <param name="remoteAddress">custom endpoint</param>
        /// <param name="logger">optional logger</param>
        public WsTrustClient(Binding binding, EndpointAddress remoteAddress, ILogger<WsTrustClient> logger = null) :
            base(binding, remoteAddress)
        {
            _logger = logger ?? TraceLogger.CreateTraceLogger<WsTrustClient>();
        }

        /// <summary>
        /// Renew a ticket
        /// </summary>
        /// <param name="sessionCert">HOK certificate</param>
        /// <param name="previousTicket">previous ticket</param>
        /// <returns>new ticket as Xml Dom element</returns>
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

        /// <summary>
        /// Request a new ticket
        /// </summary>
        /// <param name="sessionCert">HOK certificate</param>
        /// <param name="duration">requested duration of the ticket</param>
        /// <param name="claims">claims to add to the request</param>
        /// <returns>new ticket as Xml Dom element (challanges are handled internally)</returns>
        public XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, AuthClaimSet claims)
        {
            DateTime notBefore = DateTime.UtcNow;
            return RequestTicket(sessionCert, notBefore, notBefore.Add(duration), claims);
        }

        /// <summary>
        /// Request a new ticket
        /// </summary>
        /// <param name="sessionCert">HOK certificate</param>
        /// <param name="notBefore">requested start time of the ticket</param>
        /// <param name="notOnOrAfter">requested end time time of the ticket</param>
        /// <param name="claims">claims to add to the request</param>
        /// <returns>new ticket as Xml Dom element (challanges are handled internally)</returns>
        public XmlElement RequestTicket(X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, AuthClaimSet claims)
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
                        Dialect = AuthClaimSet.Dialect,
                        ClaimType =
                            claims.Select(c => new ClaimType()
                            {
                                Uri = ClaimTypeExp.Match(c.ClaimType).Groups["name"].Value, //todo::support simple names without NS.
                                Item = c.Resource
                            }).ToArray()
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
            var responseBody = new XmlDocument
            {
                PreserveWhitespace = true
            };
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

            var responseBody = new XmlDocument
            {
                PreserveWhitespace = true
            };
            responseBody.Load(responseMsg.GetReaderAtBodyContents());

            //TODO::check if correcty wrapped, but for now we do not care.
            return (XmlElement)responseBody.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:1.0:assertion")[0];
        }
    }
}