/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;
using System.Xml;
using System.IO;

namespace Siemens.EHealth.Client.Sso.Sts.WcfAddition
{
    public class EHealthMessage : Message
    {

        private Message msg;

        public EHealthMessage(Message msg)
        {
            this.msg = msg;
        }

        public override MessageHeaders Headers
        {
            get { return msg.Headers; }
        }

        public override MessageProperties Properties
        {
            get { return msg.Properties; }
        }

        public override MessageVersion Version
        {
            get { return msg.Version; }
        }

        protected override void OnClose()
        {
            base.OnClose();
            msg.Close();
        }
        /*
        protected override string OnGetBodyAttribute(string localName, string ns)
        {
            return msg.GetBodyAttribute(localName, ns);
        }
         */

        protected override void OnWriteBodyContents(System.Xml.XmlDictionaryWriter writer)
        {
            msg.WriteBodyContents(writer);
        }

        protected override void OnWriteMessage(System.Xml.XmlDictionaryWriter writer)
        {
 


            MemoryStream stream = new MemoryStream();
            XmlWriter tmpWriter = new XmlTextWriter(stream, Encoding.UTF8);
            msg.WriteMessage(tmpWriter);
            tmpWriter.Flush();

            stream.Position = 0;
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(stream);
            stream.Close();
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");
            nsmgr.AddNamespace("wssu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            nsmgr.AddNamespace("wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            nsmgr.AddNamespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
            XmlNode referenceUri = doc.SelectSingleNode("//wsse:SecurityTokenReference/wsse:Reference/@URI", nsmgr);
            if (referenceUri != null)
            {
                XmlNode referensedToken = doc.SelectSingleNode(String.Format("//wsse:BinarySecurityToken[@wssu:Id='{0}']", referenceUri.Value.Substring(1)), nsmgr);
                XmlNode unreferensedTokenId = doc.SelectSingleNode(String.Format("//wsse:BinarySecurityToken[@wssu:Id!='{0}']/@wssu:Id", referenceUri.Value.Substring(1)), nsmgr);
                if (unreferensedTokenId != null)
                {
                    referenceUri.Value = "#" + unreferensedTokenId.Value;
                    referensedToken.ParentNode.RemoveChild(referensedToken);
                }
            }
            doc.Save(writer);

            FileStream fs = new FileStream("etee.xml", FileMode.Create);
            doc.Save(fs);
            fs.Close();
        }
    }
}
