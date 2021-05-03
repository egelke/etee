using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Egelke.Wcf.Client.Helper
{
    public abstract class WSS
    {
        public abstract string Ns { get; }

        public abstract string SecExtNs { get; }

        public abstract string UtilityNs { get; }

        public abstract string TokenPofileX509Ns { get; }


        public XmlElement CreateSecurityTokenReference(string referedId)
        {
            var doc = new XmlDocument
            {
                PreserveWhitespace = true
            };

            XmlElement tokenRef = doc.CreateElement("wsse", "SecurityTokenReference", SecExtNs);

            XmlElement reference = doc.CreateElement("wsse", "Reference", SecExtNs);
            reference.SetAttribute("URI", "#" + referedId);
            reference.SetAttribute("ValueType", TokenPofileX509Ns + "#X509v3");
            tokenRef.AppendChild(reference);

            return tokenRef;
        }

        public XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            var nsmngr = new XmlNamespaceManager(document.NameTable);
            nsmngr.AddNamespace("wsu", UtilityNs);
            XmlNodeList nodes = document.SelectNodes("//*[@wsu:Id='" + idValue + "']", nsmngr);
            switch (nodes.Count)
            {
                case 0:
                    return null;
                case 1:
                    return (XmlElement)nodes[0];
                default:
                    throw new ArgumentException("Multiple instances of the ID found");
            }
        }
    }
}
