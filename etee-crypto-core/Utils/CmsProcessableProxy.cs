using Org.BouncyCastle.Cms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    class CmsProcessableProxy : CmsProcessable
    {
        private readonly Stream input;

        public CmsProcessableProxy(Stream input)
        {
            this.input = input;
        }


        [Obsolete]
        public object GetContent()
        {
            return input;
        }

        public void Write(Stream outStream)
        {
            input.CopyTo(outStream);
        }
    }
}
