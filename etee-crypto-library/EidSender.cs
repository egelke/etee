using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public sealed class EidSender : Sender
    {
        public TimeSpan WaitTime { get; set; }

        public EidSender()
        {
            WaitTime = new TimeSpan(0, 5, 0);
        }

        public EidSender(TimeSpan waitTime)
        {
            this.WaitTime = waitTime;
        }
    }
}
