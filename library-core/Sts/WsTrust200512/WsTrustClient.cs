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
            ChannelFactory<SecurityTokenServicePort> channelFactory = new ChannelFactory<SecurityTokenServicePort>(base.Endpoint.Binding, base.Endpoint.Address);
            channelFactory.Credentials.ClientCertificate.Certificate = sessionCert;
            SecurityTokenServicePort secondary = channelFactory.CreateChannel();
 
            //send the (signed) Challenge.
            response = secondary.Challenge(response);

            return response.RequestSecurityTokenResponse1.RequestedSecurityToken;
        }
    }
}