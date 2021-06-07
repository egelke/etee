using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Helper
{
    internal class KeyInfoSecurityTokenReference : KeyInfoClause
    {
        public WSS Wss { get; }

        public string ReferedID { get; set; }


        public KeyInfoSecurityTokenReference(WSS wss, string referedID)
        {
            this.Wss = wss;
            this.ReferedID = referedID;
        }

        public override XmlElement GetXml()
        {
            return Wss.CreateSecurityTokenReference(ReferedID);
        }

        public override void LoadXml(XmlElement element)
        {
            throw new NotImplementedException();
        }
    }
}
