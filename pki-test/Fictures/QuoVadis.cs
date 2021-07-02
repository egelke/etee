using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class QuoVadisFicture : RootCAFicture
    {
        public QuoVadisFicture()
        {
            CAFilePattern = @"files/QuoVadis Root CA {0}.cer";
            CACerts.Add("1 G3", "1b8eea5796291ac939eab80a811a7373c0937967");
        }
    }
}
