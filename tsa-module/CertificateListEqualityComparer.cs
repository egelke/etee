using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Client.Pki
{
    class Asn1EqualityComparer : IEqualityComparer<Asn1Encodable>
    {
        public bool Equals(Asn1Encodable x, Asn1Encodable y)
        {
            return Object.Equals(x, y);
        }

        public int GetHashCode(Asn1Encodable obj)
        {
            return obj.GetHashCode();
        }
    }
}
