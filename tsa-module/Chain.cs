using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    public class Chain
    {
        public List<ChainElement> ChainElements { get; set; }
        public List<X509ChainStatus> ChainStatus { get; set; }
    }
}
