/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.Collections.Generic;
using System.Text;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// Interface to protect messages according to the eHealth End-To-End encryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When you have a message that you want to protect and send to one or more recipients, 
    /// both identified (addressed messages) and unknown (non-addressed messages), you should 
    /// use an instance that implements this interface.
    /// </para>
    /// <para>
    /// The <see cref="EidDataSealerFactory"/> class should be used to get an instance that implements
    /// this interface.
    /// </para>
    /// <para>
    /// This interface assumes you have access to the required artififacts: the receivers ETK 
    /// or a KGSS generated key.  Retreiving the artifacts isn't part of this assembly, but this
    /// assembly is bundleled with source code that show how it can be done.
    /// </para>
    /// <para>
    /// The library does not occupy itself with the message itself.  It is always treated as an
    /// array of bytes.  If the message is text, xml or any other format, you and the receiving 
    /// parties are responsible for the correct encoding/decoding.  The library is also not 
    /// responsible of the transport of the messages.
    /// </para>
    /// </remarks>
    /// <seealso cref="EidDataSealerFactory"/>
    /// <seealso cref="EncryptionToken"/>
    /// <seealso cref="SecretKey"/>
    public interface IDataSealer
    {

        /// <summary>
        /// Seals a message for one or more known recipients via eHealth ETK's.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The message is signed, encrypted and signed again for maximum security.  The message also contains the
        /// authentication and signing certificate provided in the factory so the recipient can verify the origin.  
        /// The message also contains the following info depending on the level of which the instance was created:
        /// <list type="definition">
        /// <item>
        /// <term>B-Level</term>
        /// <description>No revocation info or time-stamp is added, no time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>T-Level</term>
        /// <description>No revocation info is added, but a time-stamp is added or a time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>LT-Level</term>
        /// <description>Revocation info is added and a time-stamp is added or a time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>LTA-Level</term>
        /// <description>For sealing this is the same as LT-Level</description>
        /// </item>
        /// </list>
        /// </para>
        /// <para>
        /// In case size of a message exteeds <see cref="Egelke.EHealth.Etee.Crypto.Configuration.Settings.InMemorySize"/> temporary files are used.  It uses the standard temporary
        /// file directory of you machine for this.  Except for catastrofical failures, these temorary files
        /// are removed when no longer needed.  It is important that you have sufficient storage in your temporaly
        /// path, about 3 times the size of the input is needed.
        /// </para>
        /// </remarks>
        /// <param name="tokens">ETK tokens, only the owners of this tokens will be able to read the message</param>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <returns>
        /// <para>
        /// The sealed message, this should be transported to the receivers.
        /// </para>
        /// <para>
        /// The stream that is returned is a FileStream to a file in the temporary folder of your machine.  The
        /// file is automaticly deleted when you dispose of the stream instance.
        /// </para>
        /// </returns>
        /// <seealso cref="Path.GetTempFileName()"/>
        /// <example>
        /// Sealing a message for several known recipient.
        /// <code lang="cs">
        /// //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// IDataSealer sealer = DataSealerFactory.Create(eidAuth, eidSign, Level.B_Level);
        /// 
        /// //Read the etk of a specific reciever
        /// EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("other1.etk"));
        /// Utils.Check(receiver1.Verify()); //verify if it is (still) correct
        /// 
        /// //Read the etk of another specific reciever
        /// EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully("other2.etk"));
        /// Utils.Check(receiver2.Verify()); //verify if it is (still) correct
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(file, receiver1, receiver2);
        /// }
        /// </code>
        /// </example>
        Stream Seal(Stream unsealed, params EncryptionToken[] tokens);

        /// <summary>
        /// Seals a message for one or more known recipients via standard certificates.
        /// </summary>
        /// <remarks>
        /// This method can be used with any encryption certificates, including certificates that aren't issued by eHealth.
        /// This should not be used in an eHealth environement!
        /// </remarks>
        /// <seealso cref="Seal(Stream, EncryptionToken[])"/>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <param name="certificates">The encryptiion certificates of the known recipients, without private key</param>
        /// <returns>The sealed message, this should be transported to the receivers.</returns>
        Stream Seal(Stream unsealed, params X509Certificate2[] certificates);

        /// <summary>
        /// Seals a message for unknown recipients and zero, one or more known recipients the same time via eHealth SecretKey and eHealth ETK's
        /// </summary>
        /// <remarks>
        /// <para>
        /// The message is signed, encrypted and signed again for maximum security.  The message also contains the
        /// authentication and signing certificate provided in the factory so the recipient can verify the origin.  
        /// The message also contains the following info depending on the level of which the instance was created:
        /// <list type="definition">
        /// <item>
        /// <term>B-Level</term>
        /// <description>No revocation info or time-stamp is added, no time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>T-Level</term>
        /// <description>No revocation info is added, but a time-stamp is added or a time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>LT-Level</term>
        /// <description>Revocation info is added and a time-stamp is added or a time-mark is required</description>
        /// </item>
        /// <item>
        /// <term>LTA-Level</term>
        /// <description>For sealing this is the same as LT-Level</description>
        /// </item>
        /// </list>
        /// </para>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by the recipients that that are specified or have access to the 
        /// same shared key.  This shared key should be retrieved from KGSS, the specified recipients
        /// can be retrieved from the ETK-Depot.
        /// </para>
        /// <para>
        /// In case size of a message exteeds <see cref="Egelke.EHealth.Etee.Crypto.Configuration.Settings.InMemorySize"/> temporary files are used.  It uses the standard temporary
        /// file directory of you machine for this.  Except for catastrofical failures, these temorary files
        /// are removed when no longer needed.  It is important that you have sufficient storage in your temporaly
        /// path, about 3 times the size of the input is needed.
        /// </para>
        /// </remarks>
        /// <param name="tokens">ETK tokens, the owners of this tokens will also be able to read the message</param>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <param name="key">KGSS shared but secret key, parties that have access to the same key can also read the messages</param>
        /// <returns>
        /// <para>
        /// The sealed message, this should be transported to the receivers.
        /// </para>
        /// <para>
        /// The stream that is returned is a FileStream to a file in the temporary folder of your machine.  The
        /// file is automaticly deleted when you dispose of the stream instance.
        /// </para>
        /// </returns>
        /// <seealso cref="Path.GetTempFileName()"/>
        /// <example>
        /// Sealing a message for both known and unknown recipient.
        /// <code lang="cs">
        /// //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// IDataSealer sealer = DataSealerFactory.Create(eidAuth, eidSign, Level.B_Level);
        /// 
        /// //Create a secret key, keyId and Key are retreived from KGSS
        /// byte[] keyId;
        /// byte[] key = Utils.GetNewSecretKey(out keyId);
        /// SecretKey skey = new SecretKey(keyId, key);
        /// 
        /// //Read the etk of a specific reciever
        /// EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("other1.etk"));
        /// Utils.Check(receiver1.Verify()); //verify if it is (still) correct
        /// 
        /// //Read the etk of another specific reciever
        /// EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully("other2.etk"));
        /// Utils.Check(receiver2.Verify()); //verify if it is (still) correct
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(file, skey, receiver1, receiver2););
        /// }
        /// </code>
        /// </example>
        Stream Seal(Stream unsealed, SecretKey key, params EncryptionToken[] tokens);
    }
}
