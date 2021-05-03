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

        public SecurityVersion MessageSecurityVersion { get; set; }

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
            using (var memStream = new MemoryStream())
            {
                //Write the document without security headers in memory
                if (_innerMessage.Properties.Encoder.MediaType != "text/xml")
                    throw new NotSupportedException("Only supports test encoding so far");
                using (var memWriter = XmlDictionaryWriter.CreateTextWriter(memStream, Encoding.UTF8, false))
                {
                    _innerMessage.WriteMessage(memWriter);
                }
                memStream.Position = 0;

                //parse the document to add the security headers
                var env = new XmlDocument();
                env.PreserveWhitespace = true;
                env.Load(memStream);

                //Make preperations to do some xpath
                string soapPrefix = env.DocumentElement.Prefix;
                string soapNs = env.DocumentElement.NamespaceURI;
                XmlNamespaceManager nsmgr = new XmlNamespaceManager(env.NameTable);
                nsmgr.AddNamespace(String.Empty, soapNs);

                //Find the soap header, create if needed.
                XmlElement header = (XmlElement) env.DocumentElement.SelectSingleNode("./Header", nsmgr);
                if (header == null)
                {
                    header = env.CreateElement(soapPrefix, "Header", soapNs);
                    env.DocumentElement.InsertBefore(header, env.DocumentElement.FirstChild);
                }

                //Parse the result
                var wss = WSS.Create(MessageSecurityVersion);
                wss.ApplyOnRequest(ref header, ClientCredentials.ClientCertificate.Certificate);

                //Write the modified version with security header to the original streams.
                env.Save(writer);
            }
        }

        /// <inheritdoc/>
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteBodyContents(writer);
        }
    }
}
