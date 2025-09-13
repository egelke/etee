using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.Sts.WsTrust200512.Error
{
    /// <summary>
    /// eHealth Fault detail error structure for SOA.
    /// </summary>
    [XmlInclude(typeof(SystemError))]
    [XmlInclude(typeof(BusinessError))]
    public abstract class SoaError : Error
    {
        /// <summary>
        /// The environment that reported the error: 
        /// Development, Test, Integration, Acceptation, Simulation or Production
        /// </summary>
        [XmlElement(Namespace = "urn:be:fgov:ehealth:errors:soa:v1")]
        public string Environment { get; set; }

        /// <inheritdoc/>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append('{')
                .Append("Origin=").Append(Origin).Append(", ")
                .Append("Code=").Append(Code).Append(", ")
                .Append("Messages=[");
            foreach(var message in Messages)
            {
                sb.Append('"').Append(message).Append("\", ");
            }
            sb.Append("], ")
                .Append("Environment=").Append(Environment)
                .Append('}');
            return sb.ToString();
        }
    }
}
