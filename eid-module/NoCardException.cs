using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    public class NoCardException : ReaderException
    {
        internal NoCardException(String msg)
            : base(msg)
        {

        }
    }
}
