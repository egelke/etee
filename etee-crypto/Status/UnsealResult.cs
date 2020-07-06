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
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// The unsealed data and additional info.
    /// </summary>
    public class UnsealResult
    {
        /// <summary>
        /// The unsealed/clear data.
        /// </summary>
        /// <value>
        /// <para>
        /// The unsealed data is never null, if any of the Unseal method of <see cref="Egelke.EHealth.Etee.Crypto.Receiver.IDataUnsealer"/> fail
        /// to extract the clear data an exception is thrown. <strong>Warning:</strong> the clear data is always
        /// provided, even if the security verification detected major violations.  Make sure you check
        ///  <see cref="SecurityInformation"/> is the data is valid and can be trusted or not.
        /// </para>
        /// <para>
        /// The property is always a stream, but can either be a MemoryStream or a Temporally FileStream, depending
        /// on the Unseal method that was invoked.  The FileStream does clean up the temporally file on closing.
        /// </para>
        /// </value>
        public Stream UnsealedData { get; internal set; }

        /// <summary>
        /// The results of the security checks.
        /// </summary>
        /// <value>
        /// This property must be used to check if the data of the <see cref="UnsealedData"/> is
        /// valid and can be trusted is not.  You should not accept any messages that have a
        /// validation status different from <see cref="ValidationStatus.Valid"/> or a trust-status
        /// different from <see cref="TrustStatus.Full"/>.
        /// </value>
        public UnsealSecurityInformation SecurityInformation { get; internal set; }


        public byte[] SenderId => SecurityInformation.OuterSignature.SignerId;

        public X509Certificate2 RecipientCertificate => SecurityInformation.Encryption.Subject?.Certificate;

        public byte[] RecipientId => SecurityInformation.Encryption.SubjectId;

        /// <summary>
        /// The sender of the message, i.e. the signer of the outer message.
        /// </summary>
        /// <value>
        /// <para>
        /// This provides information about the entity that sent the message, without vouching for the content.
        /// The information about the entity that vouches for the content can be found in <see cref="SigningCertificate"/>
        /// In general these represent the same entity, but aren't necessary the same certificate.
        /// </para>
        /// <para>
        /// The application is supposed to verify that the sender is actually
        /// allowed, the library only validate
        /// that the sender information can be used (=trusted) or not.  The definition 
        /// an validation against the list of allowed senders is out of scope
        /// for this library.
        /// </para>
        /// </value>
        public X509Certificate2 AuthenticationCertificate => SecurityInformation.OuterSignature.Signer;

        /// <summary>
        /// The issuer of the message, i.e. the signer of the inner message.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This provides information about the entity that vouching for the content of the message message, without indicating who sent it.
        /// The information about the entity that send the message can be found in <see cref="AuthenticationCertificate"/>
        /// In general these represent the same entity, but aren't necessary the same certificate.
        /// </para>
        /// </remarks>
        public X509Certificate2 SigningCertificate => SecurityInformation.InnerSignature.Signer;

        /// <summary>
        /// The value of the authentication (outer) signature.
        /// </summary>
        /// <remarks>
        /// This value is used for the time-mark authority.
        /// </remarks>
        public byte[] SignatureValue => SecurityInformation.OuterSignature.SignatureValue;

        /// <summary>
        /// The time the message was sealed on.
        /// </summary>
        public DateTime? SealedOn => SecurityInformation.OuterSignature.SigningTime;

        /// <summary>
        /// The time until the current message can be validated.
        /// </summary>
        /// <remarks>
        /// This only applies to LTA-Level where an embedded time-stamp
        /// can only be trusted as long as it can be validated with
        /// absolute certainly.
        /// </remarks>
        public DateTime? SealValidUntil => SecurityInformation.OuterSignature.TimestampRenewalTime;
        /// <summary>
        /// Indicated if the message is non repudiatable by the sender.
        /// </summary>
        public bool IsNonRepudiatable => SecurityInformation.InnerSignature.IsNonRepudiatable;

    }
}
