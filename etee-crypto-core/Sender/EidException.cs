using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// An issue with the Eid.
    /// </summary>
    public class EidException : Exception
    {
        public EidException() : base() { }

        public EidException(String msg) : base(msg) { }

        public EidException(String msg, Exception e) : base(msg, e) { }


    }
}
