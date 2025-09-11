using System;
using System.Collections.Generic;
using System.Text;
using System.Xml.Linq;

namespace Egelke.EHealth.Client.Services.Mda
{
    public class Dimension
    {
        public static string ID_REQUEST_TYPE = "requestType";

        public static string ID_CONTACT_TYPE = "contactType";

        public static string VALUE_INFORMATION = "information";

        public static string VALUE_INVOICING = "invoicing";

        public static string VALUE_OTHER = "other";

        public static string VALUE_HOSPITALIZED = "hospitalized";

        public string Id { get; set; }

        public string Value { get; set; }

        public Dimension(string id, string value) {
            Id = id;
            Value = value;
        }

        internal XElement ToXElement()
        {
            return new XElement("Dimension",
                new XAttribute("id", Id),
                Value
            );
        }
    }
}
