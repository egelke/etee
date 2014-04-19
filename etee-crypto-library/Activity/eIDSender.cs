using Egelke.EHealth.Etee.Crypto.Wf.Design;
using System;
using System.Activities;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf.Activity
{
    [Designer(typeof(eIDSenderDesigner))]
    public class eIDSender : CodeActivity
    {
        public OutArgument<Wf.Sender> To { get; set; }

        public TimeSpan WaitTime { get; set; }

        public eIDSender()
        {
            WaitTime = new TimeSpan(0, 5, 0);
        }

        protected override void Execute(CodeActivityContext context)
        {
            To.Set(context, new EidSender(WaitTime));
        }
    }
}
