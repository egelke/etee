using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Egelke.Fedict.Eid
{
    internal class CardContextSafeHandler : SafeHandleZeroOrMinusOneIsInvalid
    {
        private CardContextSafeHandler()
            : base(true)
        {

        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.SCardReleaseContext(handle) == 0;
        }
    }
}
