using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Egelke.Fedict.Eid
{
    [StructLayout(LayoutKind.Sequential)]
    internal class SCARD_IO_REQUEST
    {
        internal static readonly SCARD_IO_REQUEST T0 = new SCARD_IO_REQUEST(CardPCI.SCARD_PCI_T0);
        internal static readonly SCARD_IO_REQUEST T1 = new SCARD_IO_REQUEST(CardPCI.SCARD_PCI_T1);

        private uint dwProtocol;
        private int cbPciLength;

        private SCARD_IO_REQUEST(CardPCI protocol)
        {
            this.dwProtocol = (uint) protocol;
            this.cbPciLength = Marshal.SizeOf(typeof(SCARD_IO_REQUEST));
        }
    }
}
