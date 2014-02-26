using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    public class InvalidTokenException : Exception
    {
        public InvalidTokenException(String msg)
            : base(msg)
        {

        }

        public InvalidTokenException(String msg, Exception innerException)
            : base(msg, innerException)
        {

        }
    }
}
