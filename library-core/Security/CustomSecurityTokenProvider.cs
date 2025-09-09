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
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Sts.WsTrust200512;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using static System.Collections.Specialized.BitVector32;
using static System.Net.WebRequestMethods;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF Token Provider for eHealth.
    /// </summary>
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {
        

        private WSS _wss;

        private SecurityTokenRequirement _tokenRequirement;

        private X509Certificate2 _idCert;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="tokenRequirement">requirements for the provided token</param>
        /// <param name="idCert">the subjects certificate to request a token for</param>
        public CustomSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, X509Certificate2 idCert)
        {
            _wss = (WSS) tokenRequirement.Properties["wss"];
            _tokenRequirement = tokenRequirement;
            _idCert = idCert;
        }

        /// <summary>
        /// Obtains a token.
        /// </summary>
        /// <remarks>
        /// Supports both X509Certificate and SAML (v1.1) tokens.
        /// <para>
        /// Creates a X509Certificate token as a GenericXmlSecurityToken so it can be used by the custom applied message.
        /// </para>
        /// <para>
        /// Looks for the correct SAML token in the cache; if not found requests a new token from the STS and adds it to
        /// the cache.
        /// </para>
        /// </remarks>
        /// <param name="timeout">timeout to resprect</param>
        /// <returns>A generic xml security token that can be an X509Certificate or a SAML-Assertion with HOK</returns>
        /// <exception cref="NotSupportedException"></exception>
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            switch (_tokenRequirement.TokenType)
            {
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate":
                    return CreateX509CertificateToken();
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml":
                    return GetSamlHokToken(timeout);
                default:
                    throw new NotSupportedException("Requested token type " + _tokenRequirement.TokenType + " not supported yet");
            }
        }

        /// <summary>
        /// Create a token directly from the subject X509Certificate2.
        /// </summary>
        /// <remarks>
        /// WCF has excelent build in support for this, but returns a different token type that is internal on certain
        /// frameworks and can therefor not be used by the custom applied message implementation.
        /// </remarks>
        /// <returns>The generic xml version of the token</returns>
        protected SecurityToken CreateX509CertificateToken() {
            String id = "urn:uuid:" + Guid.NewGuid().ToString();

            XmlDocument doc = new XmlDocument();

            XmlElement bst = doc.CreateElement(_wss.SecExtPrefix, "BinarySecurityToken", WSS.SECEXT10_NS);
            XmlAttribute bstId = doc.CreateAttribute(_wss.UtilityPrefix, "Id", WSS.UTILITY_NS );
            bstId.Value = id;
            bst.Attributes.Append(bstId);
            XmlAttribute bstValueType = doc.CreateAttribute("ValueType");
            bstValueType.Value = WSS.TOKEN_PROFILE_X509_NS + "#X509v3";
            bst.Attributes.Append(bstValueType);
            XmlAttribute bstEncodingType = doc.CreateAttribute("EncodingType");
            bstEncodingType.Value = WSS.NS + "#Base64Binary";
            bst.Attributes.Append(bstEncodingType);
            XmlText bstValue = doc.CreateTextNode(Convert.ToBase64String(_idCert.RawData));
            bst.AppendChild(bstValue);

            XmlElement str = doc.CreateElement(_wss.SecExtPrefix, "SecurityTokenReference", WSS.SECEXT10_NS);
            XmlElement reference = doc.CreateElement(_wss.SecExtPrefix, "Reference", WSS.SECEXT10_NS);
            XmlAttribute uri = doc.CreateAttribute("URI");
            uri.Value = "#" + id;
            reference.Attributes.Append(uri);
            XmlAttribute valueType = doc.CreateAttribute("ValueType");
            valueType.Value = WSS.TOKEN_PROFILE_X509_NS + "#X509v3";
            reference.Attributes.Append(valueType);
            str.AppendChild(reference);

            return new GenericXmlSecurityToken(
                bst,
                new X509SecurityToken(_idCert),
                _idCert.NotBefore.ToUniversalTime(),
                _idCert.NotAfter.ToUniversalTime(),
                new GenericXmlSecurityKeyIdentifierClause(str),
                null,
                new ReadOnlyCollection<IAuthorizationPolicy>(new IAuthorizationPolicy[0])
                );
        }

        /// <summary>
        /// Obtains a SAML v1.1 token with HOK, first looks in the cache and if not found obtains a new one from the STS.
        /// </summary>
        /// <param name="timeout">The timeout to respect when obtaining the token from the STS</param>
        /// <returns>The generic xml version of the token</returns>
        protected SecurityToken GetSamlHokToken(TimeSpan timeout)
        {
            var tokenParams = _tokenRequirement.GetProperty<CustomIssuedSecurityTokenParameters>(CustomIssuedSecurityTokenParameters.IssuedSecurityTokenParametersProperty);
            var tokenId = tokenParams.ToId(_idCert);
            var token = tokenParams.Cache.Get<SecurityToken>(tokenId);

            if (token == null)
            {
                token = CreateSamlHokToken(tokenParams, timeout);
                tokenParams.Cache.Set(tokenId, token, new MemoryCacheEntryOptions()
                {
                    Size = 1,
                    AbsoluteExpiration = token.ValidTo.AddHours(1.0), //keep it for a little while longer so we can renew it if needed.
                });
            }
            else if (token.ValidTo > DateTime.Now.AddMinutes(-5.0)) //renew it a little in advance to be sure
            {
                //todo::implement
                throw new NotImplementedException();
            }
            return token;
        }

        /// <summary>
        /// Obtain a fresh token from the STS.
        /// </summary>
        /// <param name="tokenParams">parameters to obtain token</param>
        /// <param name="timeout">timeout to respect (currently ignored)</param>
        /// <returns>The generic xml version of the token</returns>
        protected SecurityToken CreateSamlHokToken(CustomIssuedSecurityTokenParameters tokenParams, TimeSpan timeout)
        {
            var client = new WsTrustClient(tokenParams.IssuerBinding, tokenParams.IssuerAddress); //todo::add logging
            client.ClientCredentials.ClientCertificate.Certificate = _idCert;
            XmlElement assertion = client.RequestTicket(tokenParams.SessionCertificate, tokenParams.SessionDuration, tokenParams.AuthClaims); //todo::use timeout

            XmlDocument doc = assertion.OwnerDocument;
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(doc.NameTable);
            nsMngr.AddNamespace("s11", "urn:oasis:names:tc:SAML:1.0:assertion");

            string id = assertion.GetAttribute("AssertionID");
            string notBefore = assertion.SelectSingleNode("./s11:Conditions/@NotBefore", nsMngr).Value;
            string notOnOrAfter = assertion.SelectSingleNode("./s11:Conditions/@NotOnOrAfter", nsMngr).Value;

            XmlElement str = doc.CreateElement(_wss.SecExtPrefix, "SecurityTokenReference", WSS.SECEXT10_NS);
            XmlAttribute tokenType = doc.CreateAttribute("wsse11", "TokenType", WSS.SECEXT11_NS);
            tokenType.Value = WSS.TOKEN_PROFILE_SAML11_NS + "#SAMLV1.1";
            str.Attributes.Append(tokenType);
            XmlElement reference = doc.CreateElement(_wss.SecExtPrefix, "KeyIdentifier", WSS.SECEXT10_NS);
            XmlAttribute valueType = doc.CreateAttribute("ValueType");
            valueType.Value = WSS.TOKEN_PROFILE_SAML10_NS + "#SAMLAssertionID";
            reference.Attributes.Append(valueType);
            reference.AppendChild(doc.CreateTextNode(id));

            str.AppendChild(reference);

            return new GenericXmlSecurityToken(
                assertion,
                new X509SecurityToken(tokenParams.SessionCertificate ?? _idCert),
                DateTime.Parse(notBefore),
                DateTime.Parse(notOnOrAfter),
                new GenericXmlSecurityKeyIdentifierClause(str),
                null,
                new ReadOnlyCollection<IAuthorizationPolicy>(new IAuthorizationPolicy[0])
                );
        }
    }
}
