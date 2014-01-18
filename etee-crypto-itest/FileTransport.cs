using Egelke.EHealth.Etee.Crypto.Library;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.ITest
{
    abstract public class FileTransport : ITransport
    {
        
        public String Content { get; set; }
        public String KekId { get; set; }

        public FileTransport(String content, String kekId)
        {
            this.Content = content;
            this.KekId = kekId;
        }

        abstract public Task<Letter> TransferAsync(Letter toSend);

        
    }
}
