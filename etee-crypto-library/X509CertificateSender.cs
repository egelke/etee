using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class X509CertificateSender : Sender
    {
        public X509Certificate2 Certificate { get; set; }
    }
}
