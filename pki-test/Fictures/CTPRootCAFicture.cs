using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class CTPRootCAFicture : RootCAFicture
    {
        public CTPRootCAFicture()
        {
            CAFilePattern = @"files/Certipost E-Trust Primary {0} CA.cer";
            CACerts.Add("Qualified", "742cdf1594049cbf17a2046cc639bb3888e02e33");
        }
    }
}
