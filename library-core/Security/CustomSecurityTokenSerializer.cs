using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityTokenSerializer : SecurityTokenSerializer
    {
        protected override bool CanReadKeyIdentifierClauseCore(XmlReader reader) => false;

        protected override bool CanReadKeyIdentifierCore(XmlReader reader) => false;

        protected override bool CanReadTokenCore(XmlReader reader) => false;

        protected override bool CanWriteKeyIdentifierClauseCore(SecurityKeyIdentifierClause keyIdentifierClause) => true;

        protected override bool CanWriteKeyIdentifierCore(SecurityKeyIdentifier keyIdentifier) => false;

        protected override bool CanWriteTokenCore(SecurityToken token) => true;

        protected override SecurityKeyIdentifierClause ReadKeyIdentifierClauseCore(XmlReader reader) => throw new NotSupportedException();

        protected override SecurityKeyIdentifier ReadKeyIdentifierCore(XmlReader reader) => throw new NotSupportedException();

        protected override SecurityToken ReadTokenCore(XmlReader reader, SecurityTokenResolver tokenResolver) => throw new NotSupportedException();

        protected override void WriteKeyIdentifierClauseCore(XmlWriter writer, SecurityKeyIdentifierClause keyIdentifierClause)
        {
            /*
            var doc = new XmlDocument
            {
                PreserveWhitespace = true
            };

            XmlElement tokenRef = doc.CreateElement("wsse", "SecurityTokenReference", SecExtNs);

            XmlElement reference = doc.CreateElement("wsse", "Reference", SecExtNs);
            reference.SetAttribute("URI", "#" + referedId);
            reference.SetAttribute("ValueType", TokenPofileX509Ns + "#X509v3");
            tokenRef.AppendChild(reference);
            */
            throw new NotImplementedException();
        }

        protected override void WriteKeyIdentifierCore(XmlWriter writer, SecurityKeyIdentifier keyIdentifier) => throw new NotSupportedException();

        protected override void WriteTokenCore(XmlWriter writer, SecurityToken token)
        {
            /*
            XmlElement bst = doc.CreateElement(SecExtPrefix, "BinarySecurityToken", SecExtNs);
            XmlAttribute bstId = doc.CreateAttribute(UtilityPrefix, "Id", UtilityNs);
            bstId.Value = "uuid-" + Guid.NewGuid().ToString("D");
            bst.Attributes.Append(bstId);
            XmlAttribute bstValueType = doc.CreateAttribute("ValueType");
            bstValueType.Value = TokenPofileX509Ns + "#X509v3";
            bst.Attributes.Append(bstValueType);
            XmlAttribute bstEncodingType = doc.CreateAttribute("EncodingType");
            bstEncodingType.Value = Ns + "#Base64Binary";
            bst.Attributes.Append(bstEncodingType);
            XmlText bstValue = doc.CreateTextNode(Convert.ToBase64String(clientCert.RawData));
            bst.AppendChild(bstValue);
            */
            throw new NotImplementedException();
        }
    }
}
