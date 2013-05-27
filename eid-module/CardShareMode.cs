using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    internal enum CardShareMode : int
    {
        SCARD_SHARE_EXCLUSIVE  = 1,
        SCARD_SHARE_SHARED = 2, //Not on CE
        SCARD_SHARE_DIRECT = 3 //Not on CE
    }
}
