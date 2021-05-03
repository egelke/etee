using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace Egelke.Wcf.Client.Helper
{
    public abstract class WSS
    {
        public static WSS Create(SecurityVersion securityVersion)
        {
            if (securityVersion == SecurityVersion.WSSecurity10)
            {
                return new WSS10();
            }
            else if (securityVersion == SecurityVersion.WSSecurity11)
            {
                throw new NotImplementedException();
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public abstract string Ns { get; }

        public abstract string SecExtNs { get; }

        public string SecExtPrefix => "wsse";

        public abstract string UtilityNs { get; }

        public string UtilityPrefix => "wsu";

        public abstract string TokenPofileX509Ns { get; }

        public void VerifyResponse(XmlElement header)
        {
            if (header.LocalName != "Security" || header.NamespaceURI != SecExtNs)
                throw new ArgumentException("Header not supported", nameof(header));


            foreach(XmlNode node in header.ChildNodes)
            {
                var xmlElement = node as XmlElement;
                if (xmlElement == null) continue;

                switch(xmlElement.LocalName)
                {
                    case "Timestamp":
                        VerifyTimestamp(xmlElement, TimeSpan.FromMinutes(5.0), TimeSpan.FromHours(1));
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }
        }

        private void VerifyTimestamp(XmlElement ts, TimeSpan clockSkewness, TimeSpan staleLimit)
        {
            DateTime created = ExtractDateFromChild(ts, "Created");
            if (created < (DateTime.UtcNow - clockSkewness)) throw new MessageSecurityException("Message created before now");

            DateTime expires = ExtractDateFromChild(ts, "Expires");
            if (DateTime.UtcNow > (expires + clockSkewness)) throw new MessageSecurityException("Message expired");
            if (DateTime.UtcNow > (created + staleLimit+ clockSkewness)) throw new MessageSecurityException("Message is stale");
        }

        private DateTime ExtractDateFromChild(XmlElement el, String name)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(el.OwnerDocument.NameTable);
            nsmgr.AddNamespace(UtilityPrefix, UtilityNs);

            XmlElement childElement = el.SelectSingleNode("./"+UtilityPrefix+":"+name, nsmgr) as XmlElement;
            if (childElement == null) throw new MessageSecurityException("Timestamp does not contain a "+name+" element");
            return DateTime.Parse(childElement.InnerText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        }

        public void ApplyOnRequest(ref XmlElement header, X509Certificate2 clientCert) {
            string soapPrefix = header.Prefix;
            string soapNs = header.NamespaceURI;
            XmlDocument doc = header.OwnerDocument;

            XmlElement sec = doc.CreateElement(SecExtPrefix, "Security", SecExtNs);
            header.AppendChild(sec);

            XmlAttribute mustUnderstand = doc.CreateAttribute(soapPrefix, "mustUnderstand", soapNs);
            mustUnderstand.Value = "1";
            sec.Attributes.Append(mustUnderstand);

            sec.SetAttribute("xmlns:" + UtilityPrefix, UtilityNs);


            XmlElement ts = doc.CreateElement(UtilityPrefix, "Timestamp", UtilityNs);
            XmlAttribute tsId = doc.CreateAttribute(UtilityPrefix, "Id", UtilityNs);
            tsId.Value = "uuid-" + Guid.NewGuid().ToString("D");
            ts.Attributes.Append(tsId);
            XmlElement created = doc.CreateElement(UtilityPrefix, "Created", UtilityNs);
            XmlText createdValue = doc.CreateTextNode(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            created.AppendChild(createdValue);
            ts.AppendChild(created);
            XmlElement expires = doc.CreateElement(UtilityPrefix, "Expires", UtilityNs);
            XmlText expiresValue = doc.CreateTextNode(DateTime.UtcNow.AddMinutes(5.0).ToString("O", CultureInfo.InvariantCulture));
            expires.AppendChild(expiresValue);
            ts.AppendChild(expires);

            sec.AppendChild(ts);

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

            sec.AppendChild(bst);

            var signedDoc = new SignedWSS(this, doc)
            {
                SigningKey = clientCert.GetRSAPrivateKey()
            };

            Reference reference = new Reference
            {
                Uri = "#" + tsId.Value,
                DigestMethod = SignedXml.XmlDsigSHA1Url
            };
            var transform = new XmlDsigExcC14NTransform();
            reference.AddTransform(transform);

            signedDoc.SignedInfo.AddReference(reference);

            signedDoc.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedDoc.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            signedDoc.KeyInfo.AddClause(new KeyInfoSecurityTokenReference(this, bstId.Value));

            signedDoc.ComputeSignature();
            XmlNode signature = signedDoc.GetXml();
            signature = doc.ImportNode(signature, true);

            sec.AppendChild(signature);
        }

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
