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
using System.IO;
using System.Security.Permissions;
using Egelke.EHealth.Etee.Crypto.Status;
using System.Security.Cryptography;

namespace Egelke.EHealth.Etee.Crypto.Receiver
{
    /// <summary>
    /// Interface to read messages that are protected according to the eHealth End-To-End encryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When you have a protected message you want to read, both identified (addressed messages) 
    /// and unknown (non-addressed messages), you should use an instance that implements this
    /// interface.
    /// </para>
    /// <para>
    /// The <see cref="DataUnsealerFactory"/> class should be used to get an instance that implements
    /// this interface.
    /// </para>
    /// <para>
    /// This interface assumes you have access to the required artifacts: your decryption certificate
    /// with private key or a KGSS generated key.  Retrieving the artifacts isn't part of this assembly, but this
    /// assembly is bundled with source code that show how it can be done.
    /// </para>
    /// <para>
    /// The library does not occupy itself with the message itself.  It is always treated as an
    /// array of bytes.  If the message is text, xml or any other format, you and the receiving 
    /// parties are responsible for the correct encoding/decoding.  The library is also not 
    /// responsible of the transport of the messages.
    /// </para>
    /// <seealso cref="DataUnsealerFactory"/>
    /// <seealso cref="SecretKey"/>
    /// <seealso cref="UnsealResult"/>
    /// </remarks>
    public interface IDataUnsealer
    {
        Dictionary<byte[], AsymmetricAlgorithm> PublicKeys { get; }

        /// <summary>
        /// Unseals a protected message of which you have the secret (but shared) key.
        /// </summary>
        /// <para>
        /// This method takes a sealed/protected message in the form of a stream and unseals it so it
        /// can be read.  It uses the key provided in the <paramref name="key"/> parameter for decryption,
        /// even if the instance contains a personal private key.  In other words, the secret key
        /// take precedence over the private key.
        /// </para>
        /// <param name="sealedData">The protected message that must be unsealed</param>
        /// <param name="key">The secret (but shared) key retrieved from the KGSS</param>
        /// <returns>
        /// <list type="bullet">
        /// <item>
        /// <description>The clear message as a temporary file stream that is deleted when the stream is closed</description>
        /// </item>
        /// <item>
        /// <description>The sender information, if known</description>
        /// </item>
        /// <item>
        /// <description>The detailed security information</description>
        /// </item>
        /// </list>
        /// </returns>
        /// <exception cref="ArgumentNullException">When sealedData and/or key is null</exception>
        /// <exception cref="InvalidMessageException">When the message can't be processed because it isn't a valid CMS message</exception>
        /// <exception cref="NotSupportedException">When the message can't be processed, but is a valid CMS message (but not necessary eHealth ETEE valid)</exception>
        /// <example>
        /// Unseal an unaddressed message
        /// <code lang="cs">
        /// //Create a IAnonymousDataSealer instance
        /// IDataSealer unsealer = DataUnsealerFactory.Create(Level.B_Level);
        /// 
        /// //Read the key id send by the sender
        /// byte[] keyId = Utils.ReadFully("protectedForGroup.kid");
        /// //Get the key from the KGSS
        /// byte[] key = GetKeyFromKGSS(keyId);
        /// //Create a secret key object
        /// SecretKey skey = new SecretKey(keyId, key);
        /// 
        /// UnsealResult result;
        /// FileStream file = new FileStream("protectedForGroup.msg", FileMode.Open);
        /// using(file)
        /// {
        ///     result = unsealer.Unseal(file, skey);
        /// }
        /// //Check if the content is in order
        /// if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid) throw new Exception(result.SecurityInformation.ToString());
        /// //Check if sender and receiver used valid and up to spec certificates
        /// if (result.SecurityInformation.TrustStatus != TrustStatus.Full) throw new Exception(result.SecurityInformation.ToString());
        /// //Check if the sender is allowed to send a message (application specific)
        /// VerifySender(result.Sender);
        /// //Use the message (application specific)
        /// ImportMessage(result.UnsealedData);
        /// </code>
        /// </example>
        UnsealResult Unseal(Stream sealedData, SecretKey key);


        /// <summary>
        /// Unseals a protected message addressed to you.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a sealed/protected message in the form of a stream and unseals it so it
        /// can be read.  It uses the personal private key to decrypt, see <see cref="DataUnsealerFactory"/> 
        /// how this private key should be provided.
        /// </para>
        /// </remarks>
        /// <param name="sealedData">The protected message that must be unsealed</param>
        /// <returns>
        /// <list type="bullet">
        /// <item>
        /// <description>The clear message as a temporary file stream that is deleted when the stream is closed</description>
        /// </item>
        /// <item>
        /// <description>The sender information, if known</description>
        /// </item>
        /// <item>
        /// <description>The detailed security information</description>
        /// </item>
        /// </list>
        /// </returns>
        /// <exception cref="ArgumentNullException">When sealedData is null</exception>
        /// <exception cref="InvalidOperationException">When the library fails because of a invalid condition</exception>
        /// <exception cref="InvalidMessageException">When the message can't be processed because it isn't a valid CMS message</exception>
        /// <exception cref="NotSupportedException">When the message can't be processed, but is a valid CMS message (but not necessary eHealth ETEE valid)</exception>
        /// <example>
        /// Unseal an addressed message
        /// <code lang="cs">
        /// //Create a IDataSealer instance
        /// var alice = new EHealthP12("alices_private_key_store.p12", "test");
        /// IDataUnsealer unsealer = DataUnsealerFactory.Create(Level.B_Level, alice);
        /// 
        /// UnsealResult result;
        /// FileStream file = new FileStream("protectedForMe.msg", FileMode.Open);
        /// using(file)
        /// {
        ///     result = unsealer.Unseal(file);
        /// }
        /// //Check if the content is in order
        /// if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid) throw new Exception(result.SecurityInformation.ToString());
        /// //Check if sender and receiver used valid and up to spec certificates
        /// if (result.SecurityInformation.TrustStatus != TrustStatus.Full) throw new Exception(result.SecurityInformation.ToString());
        /// //Check if the sender is allowed to send a message (application specific)
        /// VerifySender(result.Sender);
        /// //Use the message (application specific)
        /// ImportMessage(result.UnsealedData);
        /// </code>
        /// </example>
        UnsealResult Unseal(Stream sealedData);
    }
}
