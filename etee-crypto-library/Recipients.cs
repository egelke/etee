using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class Recipients
    {
        public List<KnownRecipient> Addressed { get; private set; }

        public UnknownRecipients Unaddressed { get; set; }

        public Recipients()
        {
            Addressed = new List<KnownRecipient>();
            Unaddressed = new UnknownRecipients();
        }
    }
}
