/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Claims;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.ServiceModel.Channels;
using System.Text.RegularExpressions;
using System.Security.Cryptography.Xml;
using System.Collections.ObjectModel;
using System.ServiceModel.Security.Tokens;

namespace Siemens.EHealth.Client.Sso.Sts.Service
{
    internal class Request
    {
        private const String samlp = "urn:oasis:names:tc:SAML:1.0:protocol";

        private const String saml = "urn:oasis:names:tc:SAML:1.0:assertion";

        private const String dsig = "http://www.w3.org/2000/09/xmldsig#";

        private const String xsi = "http://www.w3.org/2001/XMLSchema-instance";

        private const String xsd = "http://www.w3.org/2001/XMLSchema";

        public Request()
        {

        }

        public Request(String package, X509Certificate2 authCert, X509Certificate2 sessionCert, DateTime notBefore, DateTime notOnOrAfter, Collection<XmlElement> assertingClaims, Collection<ClaimTypeRequirement> requestedClaims)
        {
            body.PreserveWhitespace = true;

            this.package = package;
            this.authCert = authCert;
            this.sessionCert = sessionCert;
            this.notBefore = notBefore;
            this.notOnOrAfter = notOnOrAfter;
            this.assertingClaims = assertingClaims;
            this.requestedClaims = requestedClaims;
        }

        private bool generated = false;

        private readonly XmlDocument body = new XmlDocument();

        private readonly Regex claimTypeSplit = new Regex("{|}");

        private String requestId;

        public String RequestId
        {
            get { return requestId; }
            set { requestId = value; }
        }

        private String package;

        public String Package
        {
            get { return package; }
            set { package = value; }
        }

        private X509Certificate2 sessionCert;

        public X509Certificate2 SessionCert
        {
            get { return sessionCert; }
            set { sessionCert = value; }
        }

        private DateTime notBefore;

        public DateTime NotBefore
        {
            get { return notBefore; }
            set { notBefore = value; }
        }

        private DateTime notOnOrAfter;

        public DateTime NotOnOrAfter
        {
            get { return notOnOrAfter; }
            set { notOnOrAfter = value; }
        }

        private Collection<XmlElement> assertingClaims;

        public Collection<XmlElement> AssertingClaims
        {
            get { return assertingClaims; }
            set { assertingClaims = value; }
        }

        private Collection<ClaimTypeRequirement> requestedClaims;

        public Collection<ClaimTypeRequirement> RequestedClaims
        {
            get { return requestedClaims; }
            set { requestedClaims = value; }
        }

        private X509Certificate2 authCert;

        public X509Certificate2 AuthCert
        {
            get { return authCert; }
            set { authCert = value; }
        }

        public void Save(XmlWriter writer)
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
            
            requestId = "id-" + Guid.NewGuid().ToString();
            XmlAttribute requestIdAttr = body.CreateAttribute("RequestID");
            requestIdAttr.Value = requestId;
            request.Attributes.Append(requestIdAttr);

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

            SignedXml signed = new SamlSignedXml(body);
            signed.SigningKey = sessionCert.PrivateKey;
            signed.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signed.KeyInfo = new KeyInfo();
            signed.KeyInfo.AddClause(new KeyInfoX509Data(sessionCert, X509IncludeOption.EndCertOnly));

            Reference requestRef = new Reference("#" + requestId);
            requestRef.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            requestRef.AddTransform(new XmlDsigExcC14NTransform());
            signed.AddReference(requestRef);
            signed.ComputeSignature();
            parent.InsertBefore(signed.GetXml(), parent.FirstChild);
        }

        private void AddQuery(XmlElement parent)
        {
            XmlElement query = body.CreateElement("samlp:AttributeQuery", samlp);
            parent.AppendChild(query);

            AddSubject(query);
            foreach (ClaimTypeRequirement claim in requestedClaims)
            {
                String[] segments = claimTypeSplit.Split(claim.ClaimType);
                AddAttributeDesignator(query, segments[1], segments[2]);
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

            nameId.AppendChild(body.CreateTextNode(FormatX509Name(authCert.SubjectName)));

            XmlAttribute format = body.CreateAttribute("Format");
            format.Value = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
            nameId.Attributes.Append(format);

            XmlAttribute qualifier = body.CreateAttribute("NameQualifier");
            qualifier.Value = FormatX509Name(authCert.IssuerName); 
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
            assertionIssuer.Value = package;
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
            notBefore.Value = this.notBefore.ToString("yyyy-MM-ddTHH:mm:ssK");
            assertionConditions.Attributes.Append(notBefore);

            XmlAttribute notOnOrAfter = body.CreateAttribute("NotOnOrAfter");
            notOnOrAfter.Value = this.notOnOrAfter.ToString("yyyy-MM-ddTHH:mm:ssK");
            assertionConditions.Attributes.Append(notOnOrAfter);
        }

        private void AddAttributeStatement(XmlElement parent)
        {
            XmlElement attrStatement = body.CreateElement("saml:AttributeStatement", saml);
            parent.AppendChild(attrStatement);

            //XmlAttribute xsNsDelaration = body.CreateAttribute("xmlns:xs");
            //xsNsDelaration.Value = xsd;
            //attrStatement.Attributes.Append(xsNsDelaration);

            AddInternalSubject(attrStatement);
            foreach (XmlElement claim in assertingClaims)
            {
                XmlElement copy = (XmlElement) claim.CloneNode(true);
                XmlElement imported = (XmlElement) body.ImportNode(copy, true);
                attrStatement.AppendChild(imported);

                //String[] segments = claimTypeSplit.Split(claim.ClaimType);
                //AddAttribute(attrStatement, segments[1], segments[2], (String)claim.Resource);
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

            x509Cert.AppendChild(body.CreateTextNode(Convert.ToBase64String(sessionCert.Export(X509ContentType.Cert))));
        }

        private void AddAttribute(XmlElement parent, String ns, String name, Object value)
        {
            XmlElement attribute = body.CreateElement("saml:Attribute", saml);
            parent.AppendChild(attribute);

            XmlAttribute attributeNs = body.CreateAttribute("AttributeNamespace");
            attributeNs.Value = ns;
            attribute.Attributes.Append(attributeNs);

            XmlAttribute attributeName = body.CreateAttribute("AttributeName");
            attributeName.Value = name;
            attribute.Attributes.Append(attributeName);

            XmlElement attributeValue = body.CreateElement("saml:AttributeValue", saml);
            attribute.AppendChild(attributeValue);

            XmlAttribute attributeValueType = body.CreateAttribute("xsi:type", xsi);
            if (value is String)
            {
                
                attributeValue.AppendChild(body.CreateTextNode(value as String));
                attributeValueType.Value = "xs:string";
            }
            else
            {
                throw new InvalidCastException(String.Format("Type {0} not supported", value == null ? "<<null>>" : value.GetType().ToString()));
            }
            attributeValue.Attributes.Append(attributeValueType);
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
