using Egelke.EHealth.Client.Gmf.Msg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.Gmf
{
    public class ConsultResponse
    {
        public CommonOutputType Common { get; set; }

        public RetrieveTransactionResponseType DetailValue { get; set; }
    }
}
