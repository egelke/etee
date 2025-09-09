/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using Org.BouncyCastle.Pkcs;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Microsoft;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// To read P12 files produced by eHealth. 
    /// </summary>
    public class EHealthP12 : IDictionary<String, X509Certificate2>
    {
//        private const String SnRegExPattern = @"SERIALNUMBER=(?<sn>\d+)";
        private const String SnRegExPattern = @"SSIN=(?<sn>\d+)";

        private static readonly DerObjectIdentifier MicrosoftEnhancedRsaAndAes = MicrosoftObjectIdentifiers.Microsoft.Branch("17.1"); //(1.3.6.1.4.1.311.)17.1

        /// <summary>
        /// Find the last version of the eHealth p12 file based on the inss of the provided eid cert.
        /// </summary>
        /// <remarks>Looks for the file in the default location (%USER_PROFILE%/ehealth/keystore)</remarks>
        /// <param name="eidCert">The eid cert of a person</param>
        /// <returns>The path of the p12 for that person</returns>
        public static string FindCorresponding(X509Certificate2 eidCert)
        {
            if (eidCert == null) throw new ArgumentNullException("eidCert");

            Regex snRegex = new Regex(SnRegExPattern);
            Match snMatch = snRegex.Match(eidCert.Subject);
            if (!snMatch.Success || !snMatch.Groups["sn"].Success) throw new ArgumentException("The inserted eID has an invalid subject: " + eidCert.Subject, "eidCert");
            string sn = snMatch.Groups["sn"].Value;


            string[] files = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\ehealth\keystore", "SSIN=" + sn + "*p12");
            Array.Sort(files);

            return files[files.Length - 1];
        }

        private readonly string password;
        private readonly Pkcs12Store store;

        /// <summary>
        /// Create instance from file.
        /// </summary>
        /// <param name="file">Path to p12 store</param>
        /// <param name="pwd">The store password</param>
        public EHealthP12(String file, String pwd)
        {
            password = pwd;
            using (FileStream fileStream = new FileStream(file, FileMode.Open))
            {
                store = new Pkcs12StoreBuilder().Build();
                store.Load(fileStream, pwd.ToCharArray());
                fileStream.Close();
            }
        }

        /// <summary>
        /// Create instance from memory
        /// </summary>
        /// <param name="data">p12 store in memory</param>
        /// <param name="pwd">The store password</param>
        public EHealthP12(byte[] data, String pwd)
        {
            password = pwd;
            using (MemoryStream memStream = new MemoryStream(data))
            {
                store = new Pkcs12StoreBuilder().Build();
                store.Load(memStream, pwd.ToCharArray());
                memStream.Close();
            }
        }

        /// <summary>
        /// The aliases in the store.
        /// </summary>
        public ICollection<String> Keys
        {
            get
            {
                return store.Aliases.Cast<String>().ToList<String>();
            }
        }

        /// <summary>
        /// The certificates in the store.
        /// </summary>
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

        /// <summary>
        /// Access certificate using alias.
        /// </summary>
        /// <param name="key">The alias of the store entry</param>
        /// <returns>The certificate, optionally with key, of that alias</returns>
        /// <exception cref="KeyNotFoundException">The store doesn't contain the alias (key)</exception>
        /// <exception cref="NotSupportedException">The store is read only</exception>
        public X509Certificate2 this[String key]
        {
            get
            {
                if (key == null) new ArgumentNullException("key");

                if (TryGetValue(key, out X509Certificate2 cert))
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

        /// <summary>
        /// Add entry to the store, not supported
        /// </summary>
        /// <param name="key">The alias</param>
        /// <param name="value">The certficate</param>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Add(string key, X509Certificate2 value)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Check if the store contains the alias
        /// </summary>
        /// <param name="key">The alias to check</param>
        /// <returns>true if alias found, false otherwise</returns>
        /// <exception cref="ArgumentNullException">If the key is null</exception>
        public bool ContainsKey(string key)
        {
            if (key == null) throw new ArgumentNullException("key");

            return store.ContainsAlias(key);
        }

        /// <summary>
        /// Remove an entry from the store, not supported
        /// </summary>
        /// <param name="key">The alias</param>
        /// <returns>true if removed, false if not found</returns>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public bool Remove(string key)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Get the certficate with the provided alias of the store, safely.
        /// </summary>
        /// <param name="key">The alias</param>
        /// <param name="value">Placeholder for the certificate to be written, null if not found</param>
        /// <returns>true found, false if not found</returns>
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
        
        /// <summary>
        /// Add certificate with the provided alias.
        /// </summary>
        /// <param name="item">The certificate to add</param>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Add(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Clear all the entries from the store.
        /// </summary>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Clear()
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Verifies if certificate is present in the store with the same alias.
        /// </summary>
        /// <remarks>
        /// Uses thumbprint to verify if certificates are the same or not.
        /// </remarks>
        /// <param name="item">The alias to check and the certificate to compare with</param>
        /// <returns>true if same, false otherwise</returns>
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

        /// <summary>
        /// Copy the entries into the provided array at the requested index.
        /// </summary>
        /// <param name="array">The array to copy the entries too</param>
        /// <param name="arrayIndex">The starting index to copy too</param>
        /// <exception cref="ArgumentNullException">Array in null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Array index is negative</exception>
        /// <exception cref="ArgumentException">The array is to small</exception>
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

        /// <summary>
        /// Convert the dictionalry to a collection of certificates (with keys).
        /// </summary>
        /// <returns>X509Certificate2Collection of with all the certificates of the store</returns>
        public X509Certificate2Collection ToCollection()
        {
            X509Certificate2[] certs = new X509Certificate2[this.Count];
            this.Values.CopyTo(certs, 0);
            return new X509Certificate2Collection(certs);
        }

        /// <summary>
        /// Number of entries in the store
        /// </summary>
        public int Count
        {
            get {
                return store.Count;
            }
        }

        /// <summary>
        /// Always true, stores are read only.
        /// </summary>
        public bool IsReadOnly
        {
            get {
                return true;
            }
        }

        /// <summary>
        /// Remove an entry from the store.
        /// </summary>
        /// <param name="item">Entry to remove</param>
        /// <returns>true if removed, false otherwise</returns>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public bool Remove(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Returns a clone of the store as enumerator of alias/certificate pairs.
        /// </summary>
        /// <returns>Enumerator of the alias/certificates pairs</returns>
        public IEnumerator<KeyValuePair<string, X509Certificate2>> GetEnumerator()
        {
            //TODO:make a real enumerator
            List<KeyValuePair<string, X509Certificate2>> aliasList = new List<KeyValuePair<string, X509Certificate2>>();
            foreach (String key in Keys)
            {
                aliasList.Add(new KeyValuePair<string, X509Certificate2>(key, this[key]));
            }
#if NET40
            return new SynchronizedReadOnlyCollection<KeyValuePair<string, X509Certificate2>>(aliasList).GetEnumerator();
#else
            return aliasList.GetEnumerator();
#endif
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
        /// Installs the intermediate certificates in the "CertificateAuthority" store, if not already present.
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
                //Get the org key entry
                AsymmetricKeyEntry orgKeyEntry = store.GetKey(entryAlias);

                //Copy it into a new key attribute with the windows CSP defined
                Dictionary<DerObjectIdentifier, Asn1Encodable> newKeyEntryAttributes = new Dictionary<DerObjectIdentifier, Asn1Encodable>();
                foreach (DerObjectIdentifier attribute in orgKeyEntry.BagAttributeKeys) 
                {
                    newKeyEntryAttributes.Add(attribute, orgKeyEntry[attribute]);
                }
                if (!newKeyEntryAttributes.ContainsKey(MicrosoftEnhancedRsaAndAes))
                {
                    newKeyEntryAttributes.Add(MicrosoftEnhancedRsaAndAes, new DerBmpString("Microsoft Enhanced RSA and AES Cryptographic Provider"));
                }
                AsymmetricKeyEntry newKeyEntry = new AsymmetricKeyEntry(orgKeyEntry.Key, newKeyEntryAttributes);

                //Make a new P12 in memory
                Pkcs12Store newP12 = new Pkcs12StoreBuilder().Build();
                newP12.SetKeyEntry(entryAlias, newKeyEntry, store.GetCertificateChain(entryAlias));
                MemoryStream buffer = new MemoryStream();
                newP12.Save(buffer, password.ToCharArray(), new SecureRandom());

                //Read this P12 as X509Certificate with private key
                return new X509Certificate2(buffer.ToArray(), password, flags);
            }
            else
            {
                return new X509Certificate2(certificateEntry.Certificate.GetEncoded());
            }
        }

    }
}
