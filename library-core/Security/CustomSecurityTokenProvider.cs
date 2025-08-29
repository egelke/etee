using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

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
            XmlElement bst = doc.CreateElement("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            bst.SetAttribute("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", id);
            bst.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
            bst.SetAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            XmlText raw = doc.CreateTextNode(Convert.ToBase64String(_idCert.RawData, Base64FormattingOptions.None));
            bst.AppendChild(raw);

            XmlElement str = doc.CreateElement("SecurityTokenReference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            XmlElement reference = doc.CreateElement("Reference", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            reference.SetAttribute("URI", "#" + id);
            reference.SetAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
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
