using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class UnknownRecipients
    {
        public List<UnknownRecipient> Allowed { get; private set; }

        public List<UnknownRecipient> Excluded { get; private set; }

        public UnknownRecipients()
        {
            Allowed = new List<UnknownRecipient>();
            Excluded = new List<UnknownRecipient>();
        }
    }
}
