using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace Siemens.EHealth.Client.Sso
{
    public interface ISessionCache
    {
        XmlElement Get(String id);

        void Add(String id, XmlElement value, DateTime expires);

        void Remove(String id);
    }
}
