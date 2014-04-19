using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public sealed class eHealthP12Sender : Sender
    {
        public String FileName { get; set; }

        public String Password { get; set; }
    }
}
