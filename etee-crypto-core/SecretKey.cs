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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Represents an symetric secret key or Key Encryption Key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class represents a secret, but shared, key from the KGSS.  It can be used to seal messages so it can only be viewed by the 
    /// that the KGSS allows to retreive the same key.  It isn't advised to use the same key for more then one message.  
    /// </para>
    /// </remarks>
    public class SecretKey
    {
        private byte[] id;

        private byte[] key;

        /// <summary>
        /// Constructor for the string representation of the KEK.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The xml representation of the "GetNewKeyResponseContent" contains both the id als the key
        /// that can be provided to this constructor.  The xml representation "GetKeyResponseContent"
        /// only contains the key param for this constructor, the id param should be the same as
        /// in the xml representation of "GetKeyRequestContent".
        /// </para>
        /// </remarks>
        /// <param name="id">The ID of the KEK.  Senders get it from the KGSS web service, receivers 
        /// get it directly from the sender in an application spefic way.</param>
        /// <param name="key">The KEK itself, always retreived from the KGSS web service</param>
        public SecretKey(String id, String key)
            : this(Convert.FromBase64String(id), Convert.FromBase64String(key))
        {

        }

        /// <summary>
        /// Constuctor for the binary representation of the KEK.
        /// </summary>
        ///         /// <remarks>
        /// <para>
        /// The binary representation of the "GetNewKeyResponseContent" contains both the id als the key
        /// that can be provided to this constructor.  The binary representation "GetKeyResponseContent"
        /// only contains the key param for this constructor, the id param should be the same as
        /// in the binary representation of "GetKeyRequestContent".
        /// </para>
        /// </remarks>
        /// <param name="id">The ID of the KEK.  Senders get it from the KGSS web service, receivers 
        /// get it directly from the sender in an application spefic way</param>
        /// <param name="key">The KEK itself, always retreived from the KGSS web service</param>
        public SecretKey(byte[] id, byte[] key)
        {
            this.id = id;
            this.key = key;
        }


        /// <summary>
        /// The binary form of the KEK id.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the only part of the KEK that the application itself must transmit to the reciever,
        /// together with the message itself.  This is public information, so there is no need to seal it
        /// for transport.
        /// </para>
        /// <para>
        /// Use this representation of the KEK id if the transport support binary information.
        /// </para>
        /// </remarks>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays")]
        public byte[] Id
        {
            get
            {
                return id;
            }
        }

        /// <summary>
        /// The string form of the KEK id.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the only part of the KEK that the application itself must transmit to the reciever,
        /// together with the message itself.  This is public information, so there is no need to seal it
        /// for transport.
        /// </para>
        /// <para>
        /// Use this representation of the KEK id if the transport only support text information.
        /// </para>
        /// </remarks>
        public String IdString
        {
            get
            {
                return Convert.ToBase64String(id);
            }
        }

        internal KeyParameter BCKey
        {
            get
            {
                return new KeyParameter(key);
            }
        }

    }
}
