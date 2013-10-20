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
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Permissions;
using Siemens.EHealth.Etee.Crypto.Status;

namespace Siemens.EHealth.Etee.Crypto.Decrypt
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
    /// This interface assumes you have access to the required artififacts: your decryption certificate
    /// with private key or a KGSS generated key.  Retreiving the artifacts isn't part of this assembly, but this
    /// assembly is bundleled with source code that show how it can be done.
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
    public interface IDataUnsealer : IAnonymousDataUnsealer
    {
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
        /// <exception cref="InvalidMessageException">When the protected message isn't an correctly constructed or when the message isn't intended for you</exception>
        /// <exception cref="InvalidOperationException">When the instance of the object does not have a private key</exception>
        /// <exception cref="NotSupportedException">When the message contains multiple signatures</exception>
        /// <example>
        /// Unseal an addressed message
        /// <code lang="cs">
        /// //Create a IDataSealer instance
        /// IDataUnsealer unsealer = DataUnsealerFactory.Create(SelfEnc, SelfAuth);
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
        /// <code lang="vbnet">
        /// 'Create a IDataSealer instance
        /// Dim unsealer As IDataUnsealer = DataUnsealerFactory.Create(Utils.SelfEnc, Utils.SelfAuth)
        ///
        /// Dim result As UnsealResult
        /// Dim file As New FileStream("protectedForMe.msg", FileMode.Open)
        /// Using file
        ///     result = unsealer.Unseal(file)
        /// End Using
        /// 'Check if the content is in order
        /// If result.SecurityInformation.ValidationStatus &lt;&gt; ValidationStatus.Valid Then
        ///     Throw New Exception(result.SecurityInformation.ToString())
        /// End If
        /// 'Check if sender and receiver used valid and up to spec certificates
        /// If result.SecurityInformation.TrustStatus &lt;&gt; TrustStatus.Full Then
        ///     Throw New Exception(result.SecurityInformation.ToString())
        /// End If
        /// 'Check if the sender is allowed to send a message (application specific)
        /// VerifySender(result.Sender)
        /// 'Use the message (application specific)
        /// ImportMessage(result.UnsealedData)
        /// </code>
        /// </example>
        [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
        UnsealResult Unseal(Stream sealedData);

        /// <summary>
        /// Unseals a protected in memory message addressed to you.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method takes a sealed/protected message in the form of a byte array and unseals it so it
        /// can be read. It uses the personal private key to decrypt, see <see cref="DataUnsealerFactory"/> 
        /// how this private key should be provided.
        /// </para>
        /// </remarks>
        /// <param name="sealedData">The protected message that must be unsealed</param>
        /// <returns>
        /// <list type="bullet">
        /// <item>
        /// <description>The clear message as an in memory stream</description>
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
        /// <exception cref="InvalidMessageException">When the protected message isn't an correctly constructed or when the message isn't intended for you</exception>
        /// <exception cref="InvalidOperationException">When the instance of the object does not have a private key</exception>
        /// <exception cref="NotSupportedException">When the message contains multiple signatures</exception>
        UnsealResult Unseal(byte[] sealedData);

    }
}
