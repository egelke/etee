using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class ArrayEqualityComparer : EqualityComparer<byte[]>
    {
        public static readonly ArrayEqualityComparer Instance = new ArrayEqualityComparer();

        public override bool Equals(byte[] x, byte[] y)
        {
            return Enumerable.SequenceEqual(x, y);
        }

        public override int GetHashCode(byte[] obj)
        {
            return new BigInteger(obj).GetHashCode();
        }
    }
}
