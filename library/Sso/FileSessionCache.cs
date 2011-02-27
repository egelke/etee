using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.IO;
using System.Runtime.Serialization;

namespace Siemens.EHealth.Client.Sso
{
    internal class FileSessionCache : ISessionCache
    {
        private static readonly DataContractSerializer serializer = new DataContractSerializer(typeof(Dictionary<String, XmlElement>));

        private String fileName = @"c:\tmp\ehSessionCache.xml";

        public XmlElement Get(string id)
        {
            Dictionary<String, XmlElement> dic = Dictionary;

            XmlElement value;
            if (dic.TryGetValue(id, out value))
            {
                return value;
            }
            else
            {
                return null;
            }
        }

        public void Add(string id, XmlElement value, DateTime expires)
        {
            Dictionary<String, XmlElement> dic = Dictionary;

            dic.Add(id, value);

            Save(dic);
        }

        public void Remove(string id)
        {
            Dictionary<String, XmlElement> dic = Dictionary;

            dic.Remove(id);

            Save(dic);
        }

        private Dictionary<String, XmlElement> Dictionary
        {
            get
            {
                if (File.Exists(fileName))
                {
                    FileStream file = new FileStream(fileName, FileMode.Open);
                    using (file)
                    {
                        return (Dictionary<String, XmlElement>)serializer.ReadObject(file);
                    }
                }
                else
                {
                    return new Dictionary<string, XmlElement>();
                }
            }
        }

        private void Save(Dictionary<String, XmlElement> dictionary)
        {
            FileStream file = new FileStream(fileName, FileMode.Create);
            using (file)
            {
                serializer.WriteObject(file, dictionary);
            }
        }
    }
}
