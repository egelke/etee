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
                return store.Aliases.Cast<String>().ToList<String>();
            }
        }

        public ICollection<X509Certificate2> Values
        {
            get
            {
                List<X509Certificate2> aliasList = new List<X509Certificate2>();
                foreach (String key in Keys)
                {
                    aliasList.Add(this[key]);
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

            return store.ContainsAlias(key);
        }

        public bool Remove(string key)
        {
            throw new NotSupportedException("read only");
        }

        public bool TryGetValue(string key, out X509Certificate2 value)
        {
            if (key == null) new ArgumentNullException("key");

            if (store.ContainsAlias(key))
            {
                value = GetAsDotNet(key);
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
                return store.Count;
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
            //TODO:make a real enumerator
            List<KeyValuePair<string, X509Certificate2>> aliasList = new List<KeyValuePair<string, X509Certificate2>>();
            foreach (String key in Keys)
            {
                aliasList.Add(new KeyValuePair<string, X509Certificate2>(key, this[key]));
            }
            return new SynchronizedReadOnlyCollection<KeyValuePair<string, X509Certificate2>>(aliasList).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Install all the certificates in the correct store.
        /// </summary>
        /// <remarks>
        /// Installs the certificates with private keys in the "My" store.
        /// Installs the root certificates in the "Root" store, if not already present.
        /// Installs the intermediate certificates in the "
        /// </remarks>
        public void Install(StoreLocation location)
        {
            X509KeyStorageFlags flags = X509KeyStorageFlags.PersistKeySet
                | X509KeyStorageFlags.Exportable
                | (location == StoreLocation.CurrentUser ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.MachineKeySet);

            X509Store my = new X509Store(StoreName.My, location);
            my.Open(OpenFlags.ReadWrite);
            X509Store cas = new X509Store(StoreName.CertificateAuthority, location);
            cas.Open(OpenFlags.ReadWrite);
            X509Store root = new X509Store(StoreName.Root, location);
            root.Open(OpenFlags.ReadWrite);
            foreach (String key in Keys)
            {
                X509Certificate2 cert = GetAsDotNet(key, flags);
                if (cert.HasPrivateKey)
                {
                    my.Add(cert);
                }
                else
                {
                    X509BasicConstraintsExtension bcs = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
                    if (!bcs.CertificateAuthority) continue; //we skip unneeded certificates;
                    if (cert.Issuer != cert.Subject)
                    {
                        if (!cas.Certificates.Contains(cert)) cas.Add(cert);
                    }
                    else
                    {
                        if (!root.Certificates.Contains(cert)) root.Add(cert);
                    }
                }
            }
            my.Close();
            cas.Close();
            root.Close();
        }

        private X509Certificate2 GetAsDotNet(string entryAlias)
        {
            return GetAsDotNet(entryAlias, X509KeyStorageFlags.Exportable);
        }

        private X509Certificate2 GetAsDotNet(string entryAlias, X509KeyStorageFlags flags)
        {
            Org.BouncyCastle.Pkcs.X509CertificateEntry certificateEntry = store.GetCertificate(entryAlias);
            if (store.IsKeyEntry(entryAlias))
            {
                AsymmetricKeyEntry keyEntry = store.GetKey(entryAlias);
                Pkcs12Store newP12 = new Pkcs12Store();
                newP12.SetKeyEntry(entryAlias, keyEntry, store.GetCertificateChain(entryAlias));
                MemoryStream buffer = new MemoryStream();
                newP12.Save(buffer, password.ToCharArray(), new SecureRandom());
                return new X509Certificate2(buffer.ToArray(), password, flags);
            }
            else
            {
                return new X509Certificate2(certificateEntry.Certificate.GetEncoded());
            }
        }

    }
}
