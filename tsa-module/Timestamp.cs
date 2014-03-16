using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    public class Timestamp
    {
        public DateTime Time { get; set; }
        public DateTime RenewalTime { get; set; }
        public List<X509ChainStatus> TimestampStatus { get; set; }
        public Chain CertificateChain { get; set; }
    }
}
