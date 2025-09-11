using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.Sts.WsTrust200512.Error
{
    /// <summary>
    /// eHealth Fault detail error structure
    /// </summary>
    public class Error
    {
        /// <summary>
        /// Origin of the error (Client or Server).
        /// </summary>
        [XmlElement(Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Origin { get; set; }

        /// <summary>
        /// Error code (e.g. SOA-02001 or ws-trust:InvalidRequest)
        /// </summary>
        /// <remarks>
        /// Namespace prefixes are not parsed and my change over time.
        /// It is adviced to ignore everything before the colon sign.
        /// </remarks>
        [XmlElement(Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public string Code { get; set; }

        /// <summary>
        /// List of error messages, potentially in different languages (but normally only EN).
        /// </summary>
        [XmlElement(ElementName = "Message", Form = System.Xml.Schema.XmlSchemaForm.Unqualified)]
        public String[] Messages { get; set; }

    }
}
