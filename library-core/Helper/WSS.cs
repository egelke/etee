using Egelke.EHealth.Client.Security;
using Org.BouncyCastle.Crmf;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Client.Helper
{
    internal abstract class WSS
    {
        static WSS()
        {
            //ECDsaConfig.Init();
        }

        public static string NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";

        public static string UTILITY_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        public static string TOKEN_PROFILE_X509_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";

        public static string SECEXT_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";


        public static WSS Create(SecurityVersion securityVersion)
        {
            if (securityVersion == SecurityVersion.WSSecurity10)
            {
                return new WSS10();
            }
            else if (securityVersion == SecurityVersion.WSSecurity11)
            {
                return new WSS11();
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public string Ns => NS;

        public string SecExtNs => SECEXT_NS;

        public string SecExtPrefix => "wsse";

        public string UtilityNs => UTILITY_NS;

        public string UtilityPrefix => "wsu";

        public string TokenPofileX509Ns => TOKEN_PROFILE_X509_NS;

        public void VerifyResponse(XmlElement header)
        {
            if (header.LocalName != "Security" || header.NamespaceURI != SecExtNs)
                throw new ArgumentException("Header not supported", nameof(header));


            bool hasTimestamp = false;
            foreach(XmlNode node in header.ChildNodes)
            {
                var xmlElement = node as XmlElement;
                if (xmlElement == null) continue;

                switch(xmlElement.LocalName)
                {
                    case "Timestamp":
                        hasTimestamp = true;
                        VerifyTimestamp(xmlElement, TimeSpan.FromMinutes(5.0), TimeSpan.FromHours(1));
                        break;
                    default:
                        throw new NotSupportedException();
                }
            }
            if (!hasTimestamp) throw new MessageSecurityException("Message does not contain a timestamp");
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

        public void ApplyOnRequest(ref XmlElement header, string bodyId, X509Certificate2 clientCert, SignParts signParts) {
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
            XmlText createdValue = doc.CreateTextNode(DateTime.UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ssK", CultureInfo.InvariantCulture));
            created.AppendChild(createdValue);
            ts.AppendChild(created);
            XmlElement expires = doc.CreateElement(UtilityPrefix, "Expires", UtilityNs);
            XmlText expiresValue = doc.CreateTextNode(DateTime.UtcNow.AddMinutes(5.0).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ssK", CultureInfo.InvariantCulture));
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

            var signedDoc = new SignedWSS(this, doc);

            if (clientCert.GetRSAPrivateKey() != null)
            {
                signedDoc.SigningKey = clientCert.GetRSAPrivateKey();
                signedDoc.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            }
            else if (clientCert.GetECDsaPrivateKey() != null)
            {
                signedDoc.SigningKey = clientCert.GetECDsaPrivateKey();
                signedDoc.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            }
            else
            {
                throw new ArgumentException("Certificate key unsupported", nameof(clientCert));
            }
            signedDoc.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            if ((signParts & SignParts.Timestamp) == SignParts.Timestamp)
            {
                var reference = new Reference
                {
                    Uri = "#" + tsId.Value,
                    DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
                };
                var transform = new XmlDsigExcC14NTransform();
                reference.AddTransform(transform);

                signedDoc.SignedInfo.AddReference(reference);
            }
            if ((signParts & SignParts.Body) == SignParts.Body)
            {
                var reference = new Reference
                {
                    Uri = "#" + bodyId,
                    DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
                };
                var transform = new XmlDsigExcC14NTransform();
                reference.AddTransform(transform);

                signedDoc.SignedInfo.AddReference(reference);
            }
            if ((signParts & SignParts.BinarySecurityToken) == SignParts.BinarySecurityToken)
            {
                var reference = new Reference
                {
                    Uri = "#" + bstId.Value,
                    DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
                };
                var transform = new XmlDsigExcC14NTransform();
                reference.AddTransform(transform);

                signedDoc.SignedInfo.AddReference(reference);
            }

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
