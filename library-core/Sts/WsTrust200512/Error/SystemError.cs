using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.Sts.WsTrust200512.Error
{
    /// <summary>
    /// eHealth SOA Error that indicates an technical issue with the service itself.
    /// </summary>
    [XmlRoot(Namespace = "urn:be:fgov:ehealth:errors:soa:v1")]
    public class SystemError : SoaError
    {

    }
}
