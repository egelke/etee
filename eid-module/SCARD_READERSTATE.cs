using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Egelke.Fedict.Eid
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SCARD_READERSTATE
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public String szReader;

        public IntPtr pvUserData;

        public ReaderState dwCurrentState;

        public ReaderState dwEventState;

        public int cbAtr;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
        public byte[] rgbAtr;
    }
}
