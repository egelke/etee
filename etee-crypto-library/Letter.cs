using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Library
{
    public class Letter : IDisposable
    {
        /// <summary>
        /// The sender of the letter.
        /// </summary>
        public X509Certificate2 Sender { get; set; }

        /// <summary>
        /// The people to who the letter was sent.
        /// </summary>
        public List<Recipient> Recipients { get; set; }

        /// <summary>
        /// Additional headings that are never encrypted.
        /// </summary>
        public IDictionary<String, Object> Headers { get; set; }

        /// <summary>
        /// The content of the letter (the confidential part is applicable)
        /// </summary>
        /// <remarks>
        /// The letter takes ownership of the stream (disposed it when it is disposed)
        /// </remarks>
        public Stream Content {get; set; }

        /// <summary>
        /// The ID of the key used to encrypt the letter (if applicable)
        /// </summary>
        public byte[] ContentKeyId { get; set; }

        public Letter()
        {

        }

        public Letter(X509Certificate2 sender, List<Recipient> recipients, Stream content, IDictionary<String, Object> headers)
        {
            Sender = sender;
            Recipients = recipients;
            Content = content;
            Headers = headers;
        }

        public void Dispose()
        {
            Content.Dispose();
        }
    }
}
