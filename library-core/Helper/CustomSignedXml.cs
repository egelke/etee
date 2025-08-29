using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    public class CustomSignedXml : SignedXml
    {

        public CustomSignedXml(XmlDocument doc) : base(doc)
        {

        }

        public CustomSignedXml(XmlElement el) : base(el)
        {

        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement found = base.GetIdElement(document, idValue);
            if (found != null) return found;

            //saml request
            found = document.SelectSingleNode("//*[@RequestID=\"" + idValue + "\"]") as XmlElement;
            if (found != null) return found;

            //saml assertion
            found = document.SelectSingleNode("//*[@AssertionID=\"" + idValue + "\"]") as XmlElement;
            if (found != null) return found;

            //wss
            var nsmngr = new XmlNamespaceManager(document.NameTable);
            nsmngr.AddNamespace("wsu", WSS.UTILITY_NS);
            return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", nsmngr) as XmlElement;
        }
    }
}
