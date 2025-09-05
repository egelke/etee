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
using System.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Egelke.EHealth.Client.Helper
{
    public abstract class WSS
    {
        static WSS()
        {
            //ECDsaConfig.Init();
        }

        internal static string NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";

        internal static string UTILITY_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        internal static string TOKEN_PROFILE_X509_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";

        internal static string TOKEN_PROFILE_SAML10_NS =
            "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0";

        internal static string TOKEN_PROFILE_SAML11_NS =
            "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1";


        internal static string SECEXT10_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        internal static string SECEXT11_NS =
            "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
        


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

        //public string Ns => NS;

        //public abstract string SecExtNs { get; }

        public string SecExtPrefix => "wsse";

        //public string UtilityNs => UTILITY_NS;

        public string UtilityPrefix => "wsu";

        //public string TokenProfileX509Ns => TOKEN_PROFILE_X509_NS;

        //public string TokenProfileSaml10 => TOKEN_PROFILE_SAML10_NS;

        //public string TokenProfileSaml11 => TOKEN_PROFILE_SAML11_NS;

        public void VerifyResponse(XmlElement header)
        {
            if (header.LocalName != "Security" || header.NamespaceURI != SECEXT10_NS)
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
            nsmgr.AddNamespace(UtilityPrefix, UTILITY_NS);

            XmlElement childElement = el.SelectSingleNode("./"+UtilityPrefix+":"+name, nsmgr) as XmlElement;
            if (childElement == null) throw new MessageSecurityException("Timestamp does not contain a "+name+" element");
            return DateTime.Parse(childElement.InnerText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        }

        public void ApplyOnRequest(ref XmlElement header, string bodyId, GenericXmlSecurityToken token, SignParts signParts) {
        //public void ApplyOnRequest(ref XmlElement header, string bodyId, X509Certificate2 clientCert, SignParts signParts) {
            string soapPrefix = header.Prefix;
            string soapNs = header.NamespaceURI;
            XmlDocument doc = header.OwnerDocument;
            //note: should use "token.SecurityKeys" instead; but that will not work on Core since verything is private
            var proofToken = token.ProofToken as X509SecurityToken;

            XmlElement sec = doc.CreateElement(SecExtPrefix, "Security", SECEXT10_NS);

            XmlAttribute mustUnderstand = doc.CreateAttribute(soapPrefix, "mustUnderstand", soapNs);
            mustUnderstand.Value = "1";
            sec.Attributes.Append(mustUnderstand);
            sec.SetAttribute("xmlns:" + UtilityPrefix, UTILITY_NS);
            header.AppendChild(sec);

            XmlElement ts = doc.CreateElement(UtilityPrefix, "Timestamp", UTILITY_NS);
            XmlAttribute tsId = doc.CreateAttribute(UtilityPrefix, "Id", UTILITY_NS);
            tsId.Value = "uuid-" + Guid.NewGuid().ToString("D");
            ts.Attributes.Append(tsId);
            XmlElement created = doc.CreateElement(UtilityPrefix, "Created", UTILITY_NS);
            XmlText createdValue = doc.CreateTextNode(DateTime.UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ssK", CultureInfo.InvariantCulture));
            created.AppendChild(createdValue);
            ts.AppendChild(created);
            XmlElement expires = doc.CreateElement(UtilityPrefix, "Expires", UTILITY_NS);
            XmlText expiresValue = doc.CreateTextNode(DateTime.UtcNow.AddMinutes(5.0).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ssK", CultureInfo.InvariantCulture));
            expires.AppendChild(expiresValue);
            ts.AppendChild(expires);
            sec.AppendChild(ts);

            /*
            XmlElement bst = doc.CreateElement(SecExtPrefix, "BinarySecurityToken", SecExtNs);
            XmlAttribute bstId = doc.CreateAttribute(UtilityPrefix, "Id", UtilityNs);
            bstId.Value = token.Id;
            bst.Attributes.Append(bstId);
            XmlAttribute bstValueType = doc.CreateAttribute("ValueType");
            bstValueType.Value = TokenPofileX509Ns + "#X509v3";
            bst.Attributes.Append(bstValueType);
            XmlAttribute bstEncodingType = doc.CreateAttribute("EncodingType");
            bstEncodingType.Value = Ns + "#Base64Binary";
            bst.Attributes.Append(bstEncodingType);
            XmlText bstValue = doc.CreateTextNode(Convert.ToBase64String(proofToken.Certificate.RawData));
            bst.AppendChild(bstValue);
            var tokenXml = doc.ImportNode(bst, true);
            */

            var tokenXml = doc.ReadNode(new XmlNodeReader(token.TokenXml));
            //var tokenXml = doc.ImportNode(token.TokenXml, true);
            sec.AppendChild(tokenXml);

            var signedDoc = new CustomSignedXml(doc);
            if (proofToken.Certificate.GetRSAPrivateKey() != null)
            {
                signedDoc.SigningKey = proofToken.Certificate.GetRSAPrivateKey();
                signedDoc.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            }
            else if (proofToken.Certificate.GetECDsaPrivateKey() != null)
            {
                signedDoc.SigningKey = proofToken.Certificate.GetECDsaPrivateKey();
                signedDoc.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            }
            else
            {
                throw new ArgumentException("Certificate key unsupported", nameof(proofToken.Certificate));
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
                    Uri = "#" + token.Id,
                    DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
                };
                var transform = new XmlDsigExcC14NTransform();
                reference.AddTransform(transform);

                signedDoc.SignedInfo.AddReference(reference);
            }

            var keyIdClause = token.CreateKeyIdentifierClause<GenericXmlSecurityKeyIdentifierClause>();
            signedDoc.KeyInfo.AddClause(new CustomKeyInfoClause(keyIdClause));

            signedDoc.ComputeSignature();
            XmlNode signature = signedDoc.GetXml();
            signature = doc.ImportNode(signature, true);

            sec.AppendChild(signature);
        }

        
    }
}
