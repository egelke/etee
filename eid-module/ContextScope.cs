using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    internal enum ContextScope : int
    {
        SCARD_SCOPE_USER = 0, //Not for CE
        SCARD_SCOPE_TERMINAL = 1, //Not defined in doc
        SCARD_SCOPE_SYSTEM = 2
    }
}
