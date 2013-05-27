using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    internal enum CardDisposition : int
    {
        SCARD_LEAVE_CARD = 0,
        SCARD_RESET_CARD = 1,
        SCARD_UNPOWER_CARD = 2,
        SCARD_EJECT_CARD = 3
    }
}
