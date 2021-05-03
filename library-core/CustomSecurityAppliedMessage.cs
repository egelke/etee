using Egelke.Wcf.Client.Helper;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace Egelke.Wcf.Client
{
    /// <summary>
    /// Add the actual security headers to the message after the other channels created the message.
    /// </summary>
    /// <seealso href="https://github.com/dotnet/wcf/blob/main/src/System.Private.ServiceModel/src/System/ServiceModel/Security/SecurityAppliedMessage.cs">Insipred on</seealso>
    public class CustomSecurityAppliedMessage : Message
    {
        private Message _innerMessage;

        /// <summary>
        /// Constructor that wraps a message.
        /// </summary>
        /// <param name="innerMessage">Message from the previous channels</param>
        public CustomSecurityAppliedMessage(Message innerMessage)
        {
            _innerMessage = innerMessage;
        }

        public SecurityVersion MessageSecurityVersion
        {
            get; set;
        }

        public ClientCredentials ClientCredentials { get; set; }

        /// <inheritdoc/>
        public override bool IsEmpty
        {
            get
            {
                return _innerMessage.IsEmpty;
            }
        }

        /// <inheritdoc/>
        public override bool IsFault
        {
            get { return _innerMessage.IsFault; }
        }

        /// <inheritdoc/>
        public override MessageHeaders Headers
        {
            get { return _innerMessage.Headers; }
        }

        /// <inheritdoc/>
        public override MessageProperties Properties
        {
            get { return _innerMessage.Properties; }
        }

        /// <inheritdoc/>
        public override MessageVersion Version
        {
            get { return _innerMessage.Version; }
        }

        /// <inheritdoc/>
        protected override void OnClose()
        {
            base.OnClose();
            _innerMessage.Close();
        }

        /// <summary>
        /// Called to write the message to the writer.  This implementation add the security headers.
        /// </summary>
        /// <remarks>
        /// It writes the message to memory (of temp file) in order to do so.
        /// </remarks>
        /// <param name="writer">The xml writer to write the message too</param>
        protected override void OnWriteMessage(XmlDictionaryWriter writer)
        {
            if (_innerMessage.Properties.Encoder.MediaType != "text/xml")
                throw new NotSupportedException("Only supports test encoding so far");

            //use the upstream channels to generate the message
            var memStream = new MemoryStream();
            using (var memWriter = XmlDictionaryWriter.CreateTextWriter(memStream, Encoding.UTF8, false))
            {
                _innerMessage.WriteMessage(memWriter);
            }

            //Parse the result
            memStream.Position = 0;
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(memStream);
            memStream.Close();

            //TODO::change to message info we get pushed.
            String soapPrefix = doc.DocumentElement.Prefix;
            String soapNs = doc.DocumentElement.NamespaceURI;
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace(String.Empty, soapNs);

            //Add the security header
            XmlElement header = doc.DocumentElement.SelectSingleNode("./Header", nsmgr) as XmlElement;
            if (header == null)
            {
                header = doc.CreateElement(soapPrefix, "Header", soapNs);
                doc.DocumentElement.InsertBefore(header, doc.DocumentElement.FirstChild);
            }

            WSS wss;
            String wsseNS;
            String wsuNS;
            if (MessageSecurityVersion == SecurityVersion.WSSecurity11)
            {
                throw new NotImplementedException();
            }
            else if (MessageSecurityVersion == SecurityVersion.WSSecurity10)
            {
                wss = new WSS10();
                wsseNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
                wsuNS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            }
            else
            {
                throw new NotImplementedException();
            }
            XmlElement sec = doc.CreateElement("wsse", "Security", wsseNS);
            header.AppendChild(sec);

            XmlAttribute mustUnderstand = doc.CreateAttribute(header.Prefix, "mustUnderstand", header.NamespaceURI);
            mustUnderstand.Value = "1";
            sec.Attributes.Append(mustUnderstand);

            //sec.SetAttribute("xmlns:ws", wss.Ns);
            sec.SetAttribute("xmlns:wsu", wss.UtilityNs);
            //sec.SetAttribute("xmlns:wst", wss.TokenPofileX509Ns);


            XmlElement ts = doc.CreateElement("wsu", "Timestamp", wsuNS);
            XmlAttribute tsId = doc.CreateAttribute("wsu", "Id", wsuNS);
            tsId.Value = "uuid-" + Guid.NewGuid().ToString("D");
            ts.Attributes.Append(tsId);
            XmlElement created = doc.CreateElement("wsu", "Created", wsuNS);
            XmlText createdValue = doc.CreateTextNode(DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            created.AppendChild(createdValue);
            ts.AppendChild(created);
            XmlElement expires = doc.CreateElement("wsu", "Expires", wsuNS);
            XmlText expiresValue = doc.CreateTextNode(DateTime.UtcNow.AddMinutes(5.0).ToString("O", CultureInfo.InvariantCulture));
            expires.AppendChild(expiresValue);
            ts.AppendChild(expires);

            sec.AppendChild(ts);
            

            X509Certificate2 clientCert = ClientCredentials.ClientCertificate.Certificate;

            XmlElement bst = doc.CreateElement("wsse", "BinarySecurityToken", wsseNS);
            XmlAttribute bstId = doc.CreateAttribute("wsu", "Id", wsuNS);
            bstId.Value = "uuid-" + Guid.NewGuid().ToString("D");
            bst.Attributes.Append(bstId);
            XmlAttribute bstValueType = doc.CreateAttribute("ValueType");
            bstValueType.Value = wss.TokenPofileX509Ns + "#X509v3";
            bst.Attributes.Append(bstValueType);
            XmlAttribute bstEncodingType = doc.CreateAttribute("EncodingType");
            bstEncodingType.Value = wss.Ns + "#Base64Binary";
            bst.Attributes.Append(bstEncodingType);
            XmlText bstValue = doc.CreateTextNode(Convert.ToBase64String(clientCert.RawData));
            bst.AppendChild(bstValue);

            sec.AppendChild(bst);

            var signedDoc = new SignedWSS(wss, doc)
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

            signedDoc.KeyInfo.AddClause(new KeyInfoSecurityTokenReference(wss, bstId.Value));

            signedDoc.ComputeSignature();
            XmlNode signature = signedDoc.GetXml();
            signature = doc.ImportNode(signature, true);

            sec.AppendChild(signature);

            

            //Write modified version to the writer
            doc.Save(writer);
        }

        /*
        /// <inheritdoc/>
        protected override void OnWriteStartEnvelope(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteStartEnvelope(writer);
        }
        */


        /// <inheritdoc/>
        protected override void OnWriteStartHeaders(XmlDictionaryWriter writer)
        {
            //_innerMessage.WriteStartHeaders
        }

        /*
        /// <inheritdoc/>
        protected override void OnWriteStartBody(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteStartBody(writer);
        }
        */

        /// <inheritdoc/>
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteBodyContents(writer);
        }

        /*
        /// <inheritdoc/>
        protected override void OnBodyToString(XmlDictionaryWriter writer)
        {
            base.OnBodyToString(writer);
        }
        */

        /*
        /// <inheritdoc/>
        protected override string OnGetBodyAttribute(string localName, string ns)
        {
            return _innerMessage.GetBodyAttribute(localName, ns);
        }
        */


    }
}
