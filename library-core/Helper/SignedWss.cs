using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    internal class SignedWSS : SignedXml
    {
        public WSS Wss { get; }

        public SignedWSS(WSS wss, XmlDocument doc) : base(doc)
        {
            this.Wss = wss;
        }


        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            XmlElement found = base.GetIdElement(document, idValue);
            if (found != null) return found;

            return Wss.GetIdElement(document, idValue);
        }
    }
}
