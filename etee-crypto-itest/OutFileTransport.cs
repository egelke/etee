using Egelke.EHealth.Etee.Crypto.Library;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.ITest
{
    public class OutFileTransport : FileTransport, IDisposable
    {
        private bool disposed = false;

        public OutFileTransport(String content, String kekId)
            : base(content, kekId)
        {

        }

        override public async Task<Letter> TransferAsync(Letter outLetter)
        {
            FileStream cfs = new FileStream(Content, FileMode.Create);
            using (cfs)
            {
                Task t = outLetter.Content.CopyToAsync(cfs);

                if (outLetter.ContentKeyId != null)
                {
                    FileStream kfs = new FileStream(KekId, FileMode.Create);
                    using (kfs)
                    {
                        await kfs.WriteAsync(outLetter.ContentKeyId, 0, outLetter.ContentKeyId.Length);
                    }
                }

                await t;
            }
                
            return null;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            { 
                //cleanup managed resources (only if disposing)
                //if (disposed) noop;

                //Cleanup native resources
                if (Content != null && File.Exists(Content)) File.Delete(Content);
                if (KekId != null && File.Exists(KekId)) File.Delete(KekId);

                disposed = true;
            }
        }

        ~OutFileTransport()
        {
            Dispose(false);
        }
    }
}
