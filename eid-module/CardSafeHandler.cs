using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Egelke.Fedict.Eid
{
    internal class CardSafeHandler : SafeHandleZeroOrMinusOneIsInvalid
    {

        private CardSafeHandler()
            : base(true)
        {

        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.SCardDisconnect(handle, CardDisposition.SCARD_LEAVE_CARD) == 0;
        }
    }
}
