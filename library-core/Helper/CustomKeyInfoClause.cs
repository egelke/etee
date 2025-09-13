using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    internal class CustomKeyInfoClause : KeyInfoClause
    {
        private GenericXmlSecurityKeyIdentifierClause _other;

        public CustomKeyInfoClause(GenericXmlSecurityKeyIdentifierClause other)
        {
            _other = other;
        }

        public override XmlElement GetXml()
        {
            return _other.ReferenceXml;
        }

        public override void LoadXml(XmlElement element)
        {
            throw new NotImplementedException();
        }
    }
}
