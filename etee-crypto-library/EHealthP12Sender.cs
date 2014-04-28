using Egelke.EHealth.Client.Pki;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public sealed class EHealthP12Sender : Sender
    {
        public EHealthP12 P12 { get; set; }

        public EHealthP12Sender()
        {

        }

        public EHealthP12Sender(String fileName, String password)
        {
            P12 = new EHealthP12(fileName, password);
        }

        public EHealthP12Sender(EHealthP12 p12)
        {
            P12 = p12;
        }

    }
}
