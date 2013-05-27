using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    [AttributeUsage(AttributeTargets.Field)]
    internal class FileSelectCmdAttribute : Attribute
    {
        private byte[] cmd;

        public byte[] Cmd
        {
            get {
                return cmd;
            }
        }

        public FileSelectCmdAttribute(byte[] cmd)
        {
            this.cmd = cmd;
        }
    }
}
