/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
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
using System.Runtime.Serialization;
using System.Xml.Serialization;
using System.Xml;

namespace Siemens.EHealth.Client.Sso.WA
{
    public class XmlSerializerObjectSerializer : XmlObjectSerializer
    {
        // Fields
        private Type rootType;
        private XmlSerializer serializer;
        private XmlSerializerNamespaces ns;

        // Methods
        public XmlSerializerObjectSerializer(Type type)
        {
            this.Initialize(type);
        }

        private void Initialize(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException("type");
            }
            this.rootType = type;
            this.serializer = new XmlSerializer(type);

            ns = new XmlSerializerNamespaces();
            ns.Add("", "");

        }

        public override bool IsStartObject(XmlDictionaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException("reader");
            }
            reader.MoveToElement();
            return reader.IsStartElement();
        }

        public override object ReadObject(XmlDictionaryReader reader, bool verifyObjectName)
        {
            return this.serializer.Deserialize(reader);   
        }

        public override void WriteEndObject(XmlDictionaryWriter writer)
        {
            throw new NotImplementedException();
        }

        public override void WriteObject(XmlDictionaryWriter writer, object graph)
        {
            this.serializer.Serialize(writer, graph, ns);
        }

        public override void WriteObjectContent(XmlDictionaryWriter writer, object graph)
        {
            throw new NotImplementedException();
        }

        public override void WriteStartObject(XmlDictionaryWriter writer, object graph)
        {
            throw new NotImplementedException();
        }
    }



}
