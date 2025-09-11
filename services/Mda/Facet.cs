using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace Egelke.EHealth.Client.Services.Mda
{
    public class Facet
    {
        internal static XNamespace EXT_NS = "urn:be:cin:nippin:memberdata:saml:extension";

        public static string ID_INSURABILITY = "urn:be:cin:nippin:insurability";

        public static Facet CreateInsurability(string requestType, string contactType)
        {
            return new Facet(ID_INSURABILITY,
                new Dimension(Dimension.ID_REQUEST_TYPE, requestType),
                new Dimension(Dimension.ID_CONTACT_TYPE, contactType)
                );
        }

        public string Id { get; set; }

        public List<Dimension> Dimensions { get; } = new List<Dimension>();

        public Facet(string id, params Dimension[] dimensions)
        {
            Id = id;
            Dimensions = new List<Dimension>(dimensions);
        }
        public Facet(string id, List<Dimension> dimensions)
        {
            Id = id;
            Dimensions = dimensions;
        }

        internal XElement ToXElement()
        {
            return new XElement(EXT_NS + "Facet",
                new XAttribute("id", Id),
                Dimensions.Select(d => d.ToXElement()).ToArray()
            );
        }
    }
}
