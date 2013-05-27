using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    public class UnsupportedCardException : Exception
    {
        internal UnsupportedCardException(String msg)
            : base(msg)
        {

        }
    }
}
