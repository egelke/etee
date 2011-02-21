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
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Org.BouncyCastle.Pkcs;
using System.Security;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Security;

namespace Siemens.EHealth.Client.Tool
{
    public class EHealthP12 : IDictionary<String, X509Certificate2>
    {
        private String password;
        private Pkcs12Store store;

        public EHealthP12(String file, String pwd)
        {
            password = pwd;
            FileStream fileStream = new FileStream(file, FileMode.Open);
            using (fileStream)
            {
                store = new Pkcs12Store(fileStream, pwd.ToCharArray());
            }
        }

        public EHealthP12(byte[] data, String pwd)
        {
            password = pwd;
            MemoryStream memStream = new MemoryStream(data);
            using (memStream)
            {
                store = new Pkcs12Store(memStream, pwd.ToCharArray());
            }
        }

        public ICollection<String> Keys
        {
            get
            {
                List<String> aliasList = new List<string>();
                IEnumerator aliasEnum = store.Aliases.GetEnumerator();
                while (aliasEnum.MoveNext())
                {
                    String alias = (String)aliasEnum.Current;
                    if (store.IsKeyEntry(alias))
                    {
                        aliasList.Add(alias);
                    }
                }
                return aliasList;
            }
        }

        public ICollection<X509Certificate2> Values
        {
            get
            {
                List<X509Certificate2> aliasList = new List<X509Certificate2>();
                IEnumerator aliasEnum = store.Aliases.GetEnumerator();
                while (aliasEnum.MoveNext())
                {
                    String alias = (String)aliasEnum.Current;
                    if (store.IsKeyEntry(alias))
                    {
                        aliasList.Add(ConvertToDotNet(alias));
                    }
                }
                return aliasList;
            }
        }

        public X509Certificate2 this[String key]
        {
            get
            {
                if (key == null) new ArgumentNullException("key");

                X509Certificate2 cert;
                if (TryGetValue(key, out cert))
                {
                    return cert;
                }
                else
                {
                    throw new KeyNotFoundException();
                }
            }
            set
            {
                throw new NotSupportedException("read only");
            }
        }

        public void Add(string key, X509Certificate2 value)
        {
            throw new NotSupportedException("read only");
        }

        public bool ContainsKey(string key)
        {
            if (key == null) throw new ArgumentNullException("key");

            return store.IsKeyEntry(key);
        }

        public bool Remove(string key)
        {
            throw new NotSupportedException("read only");
        }

        public bool TryGetValue(string key, out X509Certificate2 value)
        {
            if (key == null) new ArgumentNullException("key");

            if (store.IsKeyEntry(key))
            {
                value = ConvertToDotNet(key);
                return true;
            }
            else
            {
                value = null;
                return false;
            }
        }

        public void Add(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        public void Clear()
        {
            throw new NotSupportedException("read only");
        }

        public bool Contains(KeyValuePair<string, X509Certificate2> item)
        {
            if (ContainsKey(item.Key))
            {
                X509Certificate2 cert = this[item.Key];
                if (cert == null || item.Value == null)
                {
                    return cert == null && item.Value == null;
                }
                else
                {
                    return cert.Thumbprint == item.Value.Thumbprint;
                }
            }
            else
            {
                return false;
            }
        }

        public void CopyTo(KeyValuePair<string, X509Certificate2>[] array, int arrayIndex)
        {
            if (array == null) throw new ArgumentNullException("array");
            if (arrayIndex < 0) throw new ArgumentOutOfRangeException("arrayIndex");
            if (array.Length - arrayIndex < Keys.Count) throw new ArgumentException("to small", "array");

            int i = arrayIndex;
            foreach (string key in Keys)
            {
                array[i++] = new KeyValuePair<string, X509Certificate2>(key, this[key]);
            }
        }

        public int Count
        {
            get {
                int count = 0;
                IEnumerator aliasEnum = store.Aliases.GetEnumerator();
                while (aliasEnum.MoveNext())
                {
                    String alias = (String)aliasEnum.Current;
                    if (store.IsKeyEntry(alias))
                    {
                        count++;
                    }
                }
                return count;
            }
        }

        public bool IsReadOnly
        {
            get {
                return true;
            }
        }

        public bool Remove(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        public IEnumerator<KeyValuePair<string, X509Certificate2>> GetEnumerator()
        {
            List<KeyValuePair<string, X509Certificate2>> aliasList = new List<KeyValuePair<string, X509Certificate2>>();
            IEnumerator aliasEnum = store.Aliases.GetEnumerator();
            while (aliasEnum.MoveNext())
            {
                String alias = (String)aliasEnum.Current;
                if (store.IsKeyEntry(alias))
                {
                    aliasList.Add(new KeyValuePair<string, X509Certificate2>(alias, ConvertToDotNet(alias)));
                }
            }
            return new SynchronizedReadOnlyCollection<KeyValuePair<string, X509Certificate2>>(aliasList).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        private X509Certificate2 ConvertToDotNet(string entryAlias)
        {
            AsymmetricKeyEntry keyEntry = store.GetKey(entryAlias);

            Pkcs12Store newP12 = new Pkcs12Store();
            newP12.SetKeyEntry(entryAlias, keyEntry, store.GetCertificateChain(entryAlias));
            MemoryStream buffer = new MemoryStream();
            newP12.Save(buffer, password.ToCharArray(), new SecureRandom());
            return new X509Certificate2(buffer.ToArray(), password, X509KeyStorageFlags.Exportable);
        }
    }
}
