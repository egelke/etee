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
using Microsoft.Extensions.Logging;
using static System.Collections.Specialized.BitVector32;
using static System.Net.WebRequestMethods;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {
        private WSS _wss;

        private SecurityTokenRequirement _tokenRequirement;

        private X509Certificate2 _idCert;

        public CustomSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, X509Certificate2 idCert)
        {
            _wss = (WSS) tokenRequirement.Properties["wss"];
            _tokenRequirement = tokenRequirement;
            _idCert = idCert;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            switch(_tokenRequirement.TokenType)
            {
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate":
                    return GetX509CertificateToken(timeout);
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/Saml":
                    return GetSamlHokToken(timeout);
                default:
                    throw new NotSupportedException("Requested token type "+ _tokenRequirement.TokenType + " not supported yet");
            }
        }

        protected SecurityToken GetX509CertificateToken(TimeSpan timeout) {
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

        protected SecurityToken GetSamlHokToken(TimeSpan timeout)
        {
            var tokenParams = _tokenRequirement.GetProperty<CustomIssuedSecurityTokenParameters>(CustomIssuedSecurityTokenParameters.IssuedSecurityTokenParametersProperty);

            var client = new WsTrustClient(tokenParams.IssuerBinding, tokenParams.IssuerAddress); //todo::add logging
            client.ClientCredentials.ClientCertificate.Certificate = _idCert;
            XmlElement assertion = client.RequestTicket(tokenParams.SessionCertificate, TimeSpan.FromHours(1), tokenParams.AuthClaims);

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
