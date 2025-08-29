using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Helper;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityTokenProvider : SecurityTokenProvider
    {
        private SecurityTokenRequirement _tokenRequirement;

        private X509Certificate2 _idCert;

        public CustomSecurityTokenProvider(SecurityTokenRequirement tokenRequirement, X509Certificate2 idCert)
        {
            _tokenRequirement = tokenRequirement;
            _idCert = idCert;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            switch(_tokenRequirement.TokenType)
            {
                case "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate":
                    return GetX509CertificateToken(timeout);
                default:
                    throw new NotSupportedException("Requested token type "+ _tokenRequirement.TokenType + " not supported yet");
            }
        }

        protected SecurityToken GetX509CertificateToken(TimeSpan timeout) {
            String id = "urn:uuid:" + Guid.NewGuid().ToString();

            XmlDocument doc = new XmlDocument();

            XmlElement bst = doc.CreateElement("wsse", "BinarySecurityToken", WSS.SECEXT_NS);
            XmlAttribute bstId = doc.CreateAttribute("wsu", "Id", WSS.UTILITY_NS);
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

            XmlElement str = doc.CreateElement("wsse", "SecurityTokenReference", WSS.SECEXT_NS);
            XmlElement reference = doc.CreateElement("wsse", "Reference", WSS.SECEXT_NS);
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
    }
}
