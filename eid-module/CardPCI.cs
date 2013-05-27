using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    internal enum CardPCI : uint
    {
        SCARD_PCI_T0 = 1,
        SCARD_PCI_T1 = 2,
        SCARD_PCI_RAW = 4 //not supported, but defined...
    }
}
