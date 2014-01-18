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
using System.Collections.Generic;
using System.Text;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Permissions;

namespace Egelke.EHealth.Etee.Crypto.Encrypt
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
    /// The <see cref="DataSealerFactory"/> class should be used to get an instance that implements
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
    /// <seealso cref="DataSealerFactory"/>
    /// <seealso cref="EncryptionToken"/>
    /// <seealso cref="SecretKey"/>
    public interface IDataSealer
    {
        /// <summary>
        /// Override global Offline setting if provided.
        /// </summary>
        bool? Offline { get; set; }

        /// <summary>
        /// Seals a clear in memory message for one recipient.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by one single recipient.
        /// </para>
        /// </remarks>
        /// <param name="token">ETK token, only the owner of this token will be able to read the message</param>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <returns>The sealed message, this should be transported to the receivers</returns>
        byte[] Seal(EncryptionToken token, byte[] unsealed);

        /// <summary>
        /// Seals a clear in memory message for multiple recipients.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by all the recipients that are specified.
        /// </para>
        /// </remarks>
        /// <param name="tokens">ETK tokens, only the owners of these tokens will be able to read the message</param>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <returns>The sealed message, this should be transported to the receivers</returns>
        byte[] Seal(ReadOnlyCollection<EncryptionToken> tokens, byte[] unsealed);

        /// <summary>
        /// Seals a clear message for a single recipient.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a stream and seals it so it
        /// can only be read by one single recipient.
        /// </para>
        /// <para>
        /// To limit the amount of memory needed, temporary files are used.  It uses the standard temporary
        /// file directory of you machine for this.  Except for catastrofical failures, these temorary files
        /// are removed when no longer needed.  It is important that you have sufficient storage in your temporaly
        /// path, about 3 times the size of the input is needed.
        /// </para>
        /// </remarks>
        /// <param name="token">ETK token, only the owner of this token will be able to read the message</param>
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
        /// Sealing a message for one known recipient.
        /// <code lang="cs">
        /// //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);
        /// 
        /// //Read the etk of a specific reciever
        /// EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("other.etk"));
        /// Utils.Check(receiver.Verify()); //verify if it is (still) correct
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(receiver, file);
        /// }
        /// </code>
        /// <code lang="vbnet">
        /// 'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)
        /// 
        /// 'Read the etk of a specific reciever
        /// Dim receiver As New EncryptionToken(Utils.ReadFully("other.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver.Verify())
        /// 
        /// 'Seal as stream
        /// Dim output As Stream
        /// Dim file As New FileStream("text.txt", FileMode.Open)
        /// Using file
        ///     output = sealer.Seal(receiver, file)
        /// End Using
        /// </code>
        /// </example>
        [PermissionSet(SecurityAction.LinkDemand, Name="FullTrust")]
        Stream Seal(EncryptionToken token, Stream unsealed);

        /// <summary>
        /// Seals a clear message for multiple recipients.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a stream and seals it so it
        /// can only be read by all the recipients that are specified.
        /// </para>
        /// <para>
        /// To limit the amount of memory needed, temporary files are used.  It uses the standard temporary
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
        /// IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);
        /// 
        /// //Read the etk of a specific reciever
        /// EncryptionToken receiver1 = new EncryptionToken(Utils.ReadFully("other1.etk"));
        /// Utils.Check(receiver1.Verify()); //verify if it is (still) correct
        /// 
        /// //Read the etk of another specific reciever
        /// EncryptionToken receiver2 = new EncryptionToken(Utils.ReadFully("other2.etk"));
        /// Utils.Check(receiver2.Verify()); //verify if it is (still) correct
        /// 
        /// //Create a list for the recievers, only one in this case
        /// List&lt;EncryptionToken&gt; receivers = new List&lt;EncryptionToken&gt;();
        /// receivers.Add(receiver1);
        /// receivers.Add(receiver2);
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(new ReadOnlyCollection&lt;EncryptionToken&gt;(receivers), file);
        /// }
        /// </code>
        /// <code lang="vbnet">
        /// 'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)
        /// 
        /// 'Read the etk of a specific reciever
        /// Dim receiver1 As New EncryptionToken(Utils.ReadFully("other1.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver1.Verify())
        /// 
        /// 'Read the etk of another specific reciever
        /// Dim receiver2 As New EncryptionToken(Utils.ReadFully("other2.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver2.Verify())
        /// 
        /// 'Create a list for the recievers, only one in this case
        /// Dim receivers As New List(Of EncryptionToken)
        /// receivers.Add(receiver1)
        /// receivers.Add(receiver2)
        /// 
        /// 'Seal as stream
        /// Dim output As Stream
        /// Dim file As New FileStream("text.txt", FileMode.Open)
        /// Using file
        ///     output = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), file)
        /// End Using
        /// </code>
        /// </example>
        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        Stream Seal(ReadOnlyCollection<EncryptionToken> tokens, Stream unsealed);

        /// <summary>
        /// Seals a clear message for unspecified recipients.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by the recipients that have access to the same shared key.  This shared key
        /// should be retrieved from KGSS.
        /// </para>
        /// </remarks>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <param name="key">KGSS shared but secret key, only parties that have access to the same key can read the messages</param>
        /// <returns>The sealed message, this should be transported to the receivers</returns>
        byte[] Seal(byte[] unsealed, SecretKey key);

        /// <summary>
        /// Seals a clear message for unspecified recipients.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a stream and seals it so it
        /// can only be read by the recipients that have access to the same shared key.  This shared key
        /// should be retrieved from KGSS.
        /// </para>
        /// <para>
        /// To limit the amount of memory needed, temporary files are used.  It uses the standard temporary
        /// file directory of you machine for this.  Except for catastrofical failures, these temorary files
        /// are removed when no longer needed.  It is important that you have sufficient storage in your temporaly
        /// path, about 3 times the size of the input is needed.
        /// </para>
        /// </remarks>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <param name="key">KGSS shared but secret key, only parties that have access to the same key can read the messages</param>
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
        /// IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);
        /// 
        /// //Create a secret key, keyId and Key are retreived from KGSS
        /// byte[] keyId;
        /// byte[] key = Utils.GetNewSecretKey(out keyId);
        /// SecretKey skey = new SecretKey(keyId, key);
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(file, skey);
        /// }
        /// </code>
        /// <code lang="vbnet">
        /// 'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)
        /// 
        /// 'Create a secret key, keyId and Key are retreived from KGSS
        /// Dim keyId() As Byte
        /// Dim key() As Byte = Utils.GetNewSecretKey(keyId)
        /// Dim skey As New SecretKey(keyId, key)
        /// 
        /// 'Seal as stream
        /// Dim output As Stream
        /// Dim file As New FileStream("text.txt", FileMode.Open)
        /// Using file
        ///     output = sealer.Seal(file, skey)
        /// End Using
        /// </code>
        /// </example>
        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        Stream Seal(Stream unsealed, SecretKey key);

        /// <summary>
        /// Seals a clear message for multiple recipients and unspecified recipients as the same time.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by the recipients that that are specified or have access to the 
        /// same shared key.  This shared key should be retrieved from KGSS, the specified recipients
        /// can be retrieved from the ETK-Depot.
        /// </para>
        /// </remarks>
        /// <param name="tokens">ETK tokens, the owners of this tokens will also be able to read the message</param>
        /// <param name="unsealed">The clear message that must be protected</param>
        /// <param name="key">KGSS shared but secret key, parties that have access to the same key can also read the messages</param>
        /// <returns>The sealed message, this should be transported to the receivers</returns>
        /// <example>
        /// Sealing a message for both known and unknown recipient. 
        /// <code lang="cs">
        /// String msg = "My message";
        ///
        /// //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);
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
        /// //Create a list for the recievers, only one in this case
        /// List&lt;EncryptionToken&gt; receivers = new List&lt;EncryptionToken&gt;();
        /// receivers.Add(receiver1);
        /// receivers.Add(receiver2);
        /// 
        /// //Seal a string message, encoded as UTF8.
        /// byte[] output = sealer.Seal(new ReadOnlyCollection&gt;EncryptionToken&lt;(receivers), Encoding.UTF8.GetBytes(msg), skey);
        /// </code>
        /// <code lang="vbnet">
        /// Dim msg As String = "My message"
        /// 
        /// 'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)
        /// 
        /// 'Create a secret key, keyId and Key are retreived from KGSS
        /// Dim keyId() As Byte
        /// Dim key() As Byte = Utils.GetNewSecretKey(keyId)
        /// Dim skey As New SecretKey(keyId, key)
        /// 
        /// 'Read the etk of a specific reciever
        /// Dim receiver1 As New EncryptionToken(Utils.ReadFully("other1.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver1.Verify())
        /// 
        /// 'Read the etk of another specific reciever
        /// Dim receiver2 As New EncryptionToken(Utils.ReadFully("other2.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver2.Verify())
        /// 
        /// 'Create a list for the recievers, only one in this case
        /// Dim receivers As New List(Of EncryptionToken)
        /// receivers.Add(receiver1)
        /// receivers.Add(receiver2)
        /// 
        /// 'Seal a string message, encoded as UTF8.
        /// Dim output() As Byte = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), Encoding.UTF8.GetBytes(msg), skey)
        /// </code>
        /// </example>
        byte[] Seal(ReadOnlyCollection<EncryptionToken> tokens, byte[] unsealed, SecretKey key);

        /// <summary>
        /// Seals a clear message for multiple recipients and unspecified recipients as the same time.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a clear message in the form of a byte array and seals it so it
        /// can only be read by the recipients that that are specified or have access to the 
        /// same shared key.  This shared key should be retrieved from KGSS, the specified recipients
        /// can be retrieved from the ETK-Depot.
        /// </para>
        /// <para>
        /// To limit the amount of memory needed, temporary files are used.  It uses the standard temporary
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
        /// IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);
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
        /// //Create a list for the recievers, only one in this case
        /// List&lt;EncryptionToken&gt; receivers = new List&lt;EncryptionToken&gt;();
        /// receivers.Add(receiver1);
        /// receivers.Add(receiver2);
        /// 
        /// //Seal as stream
        /// Stream output;
        /// FileStream file = new FileStream("text.txt", FileMode.Open);
        /// using (file)
        /// {
        ///     output = sealer.Seal(new ReadOnlyCollection&lt;EncryptionToken&gt;(receivers), file, skey);
        /// }
        /// </code>
        /// <code lang="vbnet">
        /// 'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        /// Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)
        /// 
        /// 'Create a secret key, keyId and Key are retreived from KGSS
        /// Dim keyId() As Byte
        /// Dim key() As Byte = Utils.GetNewSecretKey(keyId)
        /// Dim skey As New SecretKey(keyId, key)
        /// 
        /// 'Read the etk of a specific reciever
        /// Dim receiver1 As New EncryptionToken(Utils.ReadFully("other1.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver1.Verify())
        /// 
        /// 'Read the etk of another specific reciever
        /// Dim receiver2 As New EncryptionToken(Utils.ReadFully("other2.etk"))
        /// 'verify if it is (still) correct
        /// Utils.Check(receiver2.Verify())
        /// 
        /// 'Create a list for the recievers, only one in this case
        /// Dim receivers As New List(Of EncryptionToken)
        /// receivers.Add(receiver1)
        /// receivers.Add(receiver2)
        /// 
        /// 'Seal as stream
        /// Dim output As Stream
        /// Dim file As New FileStream("text.txt", FileMode.Open)
        /// Using file
        ///     output = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), file, skey)
        /// End Using
        /// </code>
        /// </example>
        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        Stream Seal(ReadOnlyCollection<EncryptionToken> tokens, Stream unsealed, SecretKey key);
    }
}
