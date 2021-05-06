/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates; 
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.ServiceModel.Channels;
using System.Security.Cryptography.Xml;
using Egelke.Wcf.Client.Helper;

namespace Egelke.Wcf.Client.Sts.Saml11
{
    internal class Request : BodyWriter
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        private const String saml = "urn:oasis:names:tc:SAML:1.0:assertion";

        private const String dsig = "http://www.w3.org/2000/09/xmldsig#";

        private const String xsi = "http://www.w3.org/2001/XMLSchema-instance";

        private const String xsd = "http://www.w3.org/2001/XMLSchema";

        public Request() : base(false)
        {
            body = new XmlDocument
            {
                PreserveWhitespace = true
            };
        }

        private bool generated = false;

        private readonly XmlDocument body;

        public String RequestId { get; set; }

        public String Package { get; set; }

        public X509Certificate2 SessionCert { get; set; }

        public DateTime NotBefore { get; set; }

        public DateTime NotOnOrAfter { get; set; }

        public IList<XmlElement> AssertingClaims { get; set; }

        public IList<XmlElement> RequestedClaims { get; set; }

        public X509Certificate2 AuthCert { get; set; }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            if (!generated) Generate();
            body.Save(writer);
        }

        public void Generate()
        {
            if (generated) throw new InvalidOperationException("You can't generate a request twise");
            generated = true;

            XmlElement request = body.CreateElement("samlp:Request", samlp);
            body.AppendChild(request);
            
            RequestId = "uuid-" + Guid.NewGuid().ToString();
            XmlAttribute requestIdAttr = body.CreateAttribute("RequestID");
            requestIdAttr.Value = RequestId;
            request.SetAttributeNode(requestIdAttr);

            AddStandardAttributes(request);
            AddQuery(request);
            AddSignature(request);
        }

        private void AddStandardAttributes(XmlElement parent)
        {
            XmlAttribute majorVersion = body.CreateAttribute("MajorVersion");
            majorVersion.Value = "1";
            XmlAttribute minorVersion = body.CreateAttribute("MinorVersion");
            minorVersion.Value = "1";
            XmlAttribute issueInstant = body.CreateAttribute("IssueInstant");
            issueInstant.Value = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssK");
            
            parent.Attributes.Append(majorVersion);
            parent.Attributes.Append(minorVersion);
            parent.Attributes.Append(issueInstant);
        }

        private void AddSignature(XmlElement parent)
        {
            body.Normalize();

            SignedXml signed = new SignedSaml11(body);
            signed.SigningKey = SessionCert.PrivateKey;
            signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signed.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signed.KeyInfo = new KeyInfo();
            signed.KeyInfo.AddClause(new KeyInfoX509Data(SessionCert, X509IncludeOption.EndCertOnly));

            Reference requestRef = new Reference("#" + RequestId);
            requestRef.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            requestRef.AddTransform(new XmlDsigExcC14NTransform());
            requestRef.DigestMethod = SignedXml.XmlDsigSHA1Url;
            signed.AddReference(requestRef);
            signed.ComputeSignature();
            parent.InsertBefore(signed.GetXml(), parent.FirstChild);
        }

        private void AddQuery(XmlElement parent)
        {
            XmlElement query = body.CreateElement("samlp:AttributeQuery", samlp);
            parent.AppendChild(query);

            AddSubject(query);
            foreach (XmlElement claim in RequestedClaims)
            {
                AddAttributeDesignator(query, claim.GetAttribute("AttributeNamespace"), claim.GetAttribute("AttributeName"));
            }
        }

        private void AddSubject(XmlElement parent)
        {
            XmlElement subject = body.CreateElement("saml:Subject", saml);
            parent.AppendChild(subject);

            AddNameIdentifier(subject);
            AddSubjectConfirmation(subject);
        }

        private void AddNameIdentifier(XmlElement parent)
        {
            XmlElement nameId = body.CreateElement("saml:NameIdentifier", saml);
            parent.AppendChild(nameId);

            nameId.AppendChild(body.CreateTextNode(FormatX509Name(AuthCert.SubjectName)));

            XmlAttribute format = body.CreateAttribute("Format");
            format.Value = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
            nameId.Attributes.Append(format);

            XmlAttribute qualifier = body.CreateAttribute("NameQualifier");
            qualifier.Value = FormatX509Name(AuthCert.IssuerName); 
            nameId.Attributes.Append(qualifier);
        }

        private void AddSubjectConfirmation(XmlElement parent)
        {
            XmlElement subjectConfirm = body.CreateElement("saml:SubjectConfirmation", saml);
            parent.AppendChild(subjectConfirm);

            AddConfirmationMethod(subjectConfirm);
            AddSubjectConfirmationData(subjectConfirm);
            AddKeyInfo(subjectConfirm);
        }

        private void AddConfirmationMethod(XmlElement parent)
        {
            XmlElement subjectconfirmMethod = body.CreateElement("saml:ConfirmationMethod", saml);
            parent.AppendChild(subjectconfirmMethod);

            subjectconfirmMethod.AppendChild(body.CreateTextNode("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"));
        }

        private void AddSubjectConfirmationData(XmlElement parent)
        {
            XmlElement subjectConfirmData = body.CreateElement("saml:SubjectConfirmationData", saml);
            parent.AppendChild(subjectConfirmData);

            AddAssertion(subjectConfirmData);
        }

        private void AddAssertion(XmlElement parent)
        {
            XmlElement assertion = body.CreateElement("saml:Assertion", saml);
            parent.AppendChild(assertion);

            AddStandardAttributes(assertion);

            XmlAttribute assertionIssuer = body.CreateAttribute("Issuer");
            assertionIssuer.Value = Package;
            assertion.Attributes.Append(assertionIssuer);

            XmlAttribute assertionId = body.CreateAttribute("AssertionID");
            assertionId.Value = "id-" + Guid.NewGuid().ToString();
            assertion.Attributes.Append(assertionId);

            AddConditions(assertion);
            AddAttributeStatement(assertion);
        }

        private void AddConditions(XmlElement parent)
        {
            XmlElement assertionConditions = body.CreateElement("saml:Conditions", saml);
            parent.AppendChild(assertionConditions);

            XmlAttribute notBefore = body.CreateAttribute("NotBefore");
            notBefore.Value = this.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssK");
            assertionConditions.Attributes.Append(notBefore);

            XmlAttribute notOnOrAfter = body.CreateAttribute("NotOnOrAfter");
            notOnOrAfter.Value = this.NotOnOrAfter.ToString("yyyy-MM-ddTHH:mm:ssK");
            assertionConditions.Attributes.Append(notOnOrAfter);
        }

        private void AddAttributeStatement(XmlElement parent)
        {
            XmlElement attrStatement = body.CreateElement("saml:AttributeStatement", saml);
            parent.AppendChild(attrStatement);

            AddInternalSubject(attrStatement);
            foreach (XmlElement claim in AssertingClaims)
            {
                ImportAttribute(attrStatement, claim);
            }
        }

        private void AddInternalSubject(XmlElement parent)
        {
            XmlElement attrStatementSubject = body.CreateElement("saml:Subject", saml);
            parent.AppendChild(attrStatementSubject);

            AddNameIdentifier(attrStatementSubject);
        }

        private void AddKeyInfo(XmlElement parent)
        {
            XmlElement keyInfo = body.CreateElement("ds:KeyInfo", dsig);
            parent.AppendChild(keyInfo);

            AddX509Data(keyInfo);
        }

        private void AddX509Data(XmlElement parent)
        {
            XmlElement x509Data = body.CreateElement("ds:X509Data", dsig);
            parent.AppendChild(x509Data);

            AddX509Certificate(x509Data);
        }

        private void AddX509Certificate(XmlElement parent)
        {
            XmlElement x509Cert = body.CreateElement("ds:X509Certificate", dsig);
            parent.AppendChild(x509Cert);

            x509Cert.AppendChild(body.CreateTextNode(Convert.ToBase64String(SessionCert.Export(X509ContentType.Cert))));
        }

        private void ImportAttribute(XmlElement parent, XmlElement org)
        {
            XmlElement attribute = body.CreateElement("saml:Attribute", saml);
            parent.AppendChild(attribute);

            XmlAttribute attributeNs = body.CreateAttribute("AttributeNamespace");
            attributeNs.Value = org.GetAttribute("AttributeNamespace");
            attribute.Attributes.Append(attributeNs);

            XmlAttribute attributeName = body.CreateAttribute("AttributeName");
            attributeName.Value = org.GetAttribute("AttributeName");
            attribute.Attributes.Append(attributeName);

            foreach(XmlElement orgValue in org.GetElementsByTagName("AttributeValue", saml))
            {
                XmlElement attributeValue = body.CreateElement("saml:AttributeValue", saml);
                attributeValue.InnerText = orgValue.InnerText;

                XmlAttribute attributeValueType = body.CreateAttribute("xsi:type", xsi);
                String attributeValueTypeValue = orgValue.GetAttribute("type", xsi);
                String[] valueParts = attributeValueTypeValue.Split(':');
                if (valueParts.Length > 1) {
                    String orgPrefix = valueParts[0];
                    String ns = orgValue.GetNamespaceOfPrefix(orgPrefix);
                    String newPrefix = attributeValue.GetPrefixOfNamespace(ns);
                    if (String.IsNullOrEmpty(newPrefix))
                    {
                        attributeValue.SetAttribute("xmlns:" + orgPrefix, ns);
                        attributeValueType.Value = attributeValueTypeValue;
                    }
                    else 
                    {
                        attributeValueType.Value = newPrefix + ":" + valueParts[1];
                    }
                } 
                else
                {
                    attributeValueType.Value = attributeValueTypeValue;
                }
                attributeValue.Attributes.Append(attributeValueType);

                attribute.AppendChild(attributeValue);
            }
        }

        private void AddAttributeDesignator(XmlElement parent, String ns, String name)
        {
            XmlElement reqAttibute = body.CreateElement("saml:AttributeDesignator", saml);
            parent.AppendChild(reqAttibute);

            XmlAttribute reqAttributeNs = body.CreateAttribute("AttributeNamespace");
            reqAttributeNs.Value = ns;
            reqAttibute.Attributes.Append(reqAttributeNs);

            XmlAttribute reqAttributeName = body.CreateAttribute("AttributeName");
            reqAttributeName.Value = name;
            reqAttibute.Attributes.Append(reqAttributeName);
        }

        private static String FormatX509Name(X500DistinguishedName name)
        {
            Asn1StreamParser parser = new Asn1StreamParser(name.RawData);
            X509Name _name = X509Name.GetInstance(parser.ReadObject().ToAsn1Object());
            return _name.ToString(true, X509Name.RFC1779Symbols);
        }


    }


}
