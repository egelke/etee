using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Services.Mda
{
    public interface IMda
    {
        XmlElement CreateQuery(string ssin, DateTime start, DateTime end, params Facet[] facets);

        IEnumerable<XmlElement> Consult(XmlElement query);
    }
}
