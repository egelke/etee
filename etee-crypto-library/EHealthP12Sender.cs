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
        public String FileName { get; set; }

        public String Password { get; set; }

        public EHealthP12Sender()
        {

        }

        public EHealthP12Sender(String fileName, String password)
        {
            this.FileName = fileName;
            this.Password = password;
        }

        internal EHealthP12 ToEHealthP12()
        {
            return new EHealthP12(FileName, Password);
        }
    }
}
