using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class ZTRootCAFicture : RootCAFicture
    {
        public ZTRootCAFicture()
        {
            CAFilePattern = @"files/ZetesConfidens Private Trust PKI - root CA {0}.cer";
            CACerts.Add("001", "1acfcb1b0dfef7a237f79057a7c9cc41f3708705");
        }
    }
}
