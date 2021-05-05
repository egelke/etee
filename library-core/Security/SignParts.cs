using System;
using System.Collections.Generic;
using System.Text;

namespace Egelke.Wcf.Client.Security
{
    [Flags]
    public enum SignParts : int
    {
        Timestamp           = 0x01,
        Body                = 0x02,
        BinarySecurityToken = 0x04,
        All                 = Timestamp | Body | BinarySecurityToken
    }
}
