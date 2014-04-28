using Egelke.EHealth.Client.Pki;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class Receiver
    {
        public List<EHealthP12> Addressed { get; private set; }

        public Receiver()
        {
            Addressed = new List<EHealthP12>();
        }
    }
}
