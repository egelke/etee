using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    public class ChainElement
    {
        public ChainElement()
        {
            this.ChainElementStatus = new List<X509ChainStatus>();
        }

        internal ChainElement(X509ChainElement source)
            : this()
        {
            this.Certificate = source.Certificate;
            this.ChainElementStatus.AddRange(source.ChainElementStatus);
        }

        public X509Certificate2 Certificate { get; set; }

        public List<X509ChainStatus> ChainElementStatus { get; set; }
    }

    
}
