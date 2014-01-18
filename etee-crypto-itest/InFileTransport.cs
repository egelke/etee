using Egelke.EHealth.Etee.Crypto.Library;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.ITest
{
    public class InFileTransport : FileTransport
    {
        public InFileTransport(String Content, String KekId)
            : base(Content, KekId)
        {

        }

        override public async Task<Letter> TransferAsync(Letter outLetter)
        {
            Letter inLetter = new Letter();
            
            FileStream kfs = new FileStream(KekId, FileMode.Open);
            using (kfs)
            {
                inLetter.ContentKeyId = new byte[kfs.Length];
                await kfs.ReadAsync(inLetter.ContentKeyId, 0, inLetter.ContentKeyId.Length);
            }

            inLetter.Content = File.OpenRead(Content);

            return inLetter;
        }
    }
}
