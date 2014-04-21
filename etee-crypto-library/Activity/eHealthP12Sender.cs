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
    [Designer(typeof(eHealthP12SenderDesigner))]
    public class eHealthP12Sender : CodeActivity
    {
        public OutArgument<Wf.Sender> To { get; set; }

        public InArgument<String> FileName { get; set; }

        public InArgument<String> Password { get; set; }

        public eHealthP12Sender()
        {
        }

        protected override void Execute(CodeActivityContext context)
        {
            String file = FileName.Get(context);
            String pwd = Password.Get(context);
            To.Set(context, new Wf.EHealthP12Sender(file, pwd));
        }
    }
}
