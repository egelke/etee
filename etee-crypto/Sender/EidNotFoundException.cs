using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// eID card not present or not found.
    /// </summary>
    /// <remarks>
    /// The eID isn't present or not found (e.g. middleware not installed).
    /// </remarks>
    public class EidNotFoundException : EidException
    {

        public EidNotFoundException() : base() { }

        public EidNotFoundException(String msg) : base(msg) { }

        public EidNotFoundException(String msg, Exception e) : base(msg, e) { }
    }
}
