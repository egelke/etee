using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    [Flags]
    internal enum CardProtocols : int
    {
        SCARD_PROTOCOL_UNDEFINED = 0,
        SCARD_PROTOCOL_T0 = 1,
        SCARD_PROTOCOL_T1 = 2

    }
}
