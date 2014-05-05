using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Gmf
{
    public class ArchivingInfo
    {
        public BlobType RequestDetail { get; set; }

        public base64Binary RequestXadesT { get; set; }

        public BlobType ResponseDetail { get; set; }

        public base64Binary ResponseXadesT { get; set; }
    }
}
