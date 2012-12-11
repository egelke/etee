using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.IO;
using System.Runtime.Serialization;
using System.Threading;
using System.Security.Cryptography;

namespace Siemens.EHealth.Client.Sso
{
    public class FileSessionCache : ISessionCache
    {
        private static readonly DataContractSerializer serializer = new DataContractSerializer(typeof(XmlElement));

        private static readonly SHA1 sha = SHA1.Create();

        private String path;

        public FileSessionCache(XmlDocument config)
        {
            if (config == null || config.GetElementsByTagName("path").Count == 0)
            {
                path = Path.GetTempPath();
            }
            else
            {
                path = config.GetElementsByTagName("path")[0].InnerText;
            }
        }

        public XmlElement Get(string id)
        {
            FileStream stream = null;
            try
            {
                stream = new FileStream(ToFileName(id), FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch (FileNotFoundException)
            {
                return null;
            }

            using (stream)
            {
                return (XmlElement) serializer.ReadObject(stream);
            }
        }

        public void Add(string id, XmlElement value, DateTime expires)
        {
            FileStream stream = null;
            String fileName = ToFileName(id);
            try
            {
                stream = new FileStream(fileName, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException ioe)
            {
                if (File.Exists(fileName))
                {
                    //The file exits, so we should not create it any more
                    return;
                }
                else
                {
                    throw ioe;
                }
            }
            using (stream)
            {
                serializer.WriteObject(stream, value);
            }
        }

        public void Remove(string id)
        {
            try
            {
                File.Delete(ToFileName(id));
            }
            catch (DirectoryNotFoundException)
            {
                //If not found, then it already gone...
            }
        }

        private String ToFileName(string id)
        {
            byte[] buffer = new byte[16];
            Array.Copy(sha.ComputeHash(Encoding.UTF8.GetBytes(id)), buffer, buffer.Length);
            return path + @"\" + new Guid(buffer).ToString() + ".xml";
        }
    }
}
