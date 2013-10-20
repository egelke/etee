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
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// The unsealed data and additional info.
    /// </summary>
    public class UnsealResult
    {
        private Stream unsealedData;

        private UnsealSecurityInformation securityInformation;

        /// <summary>
        /// The unsealed/clear data.
        /// </summary>
        /// <value>
        /// <para>
        /// The unsealed data is never null, if any of the Unseal method of <see cref="IDataUnsealer"/> fail
        /// to extract the clear data an exception is thrown. <strong>Warning:</strong> the clear data is always
        /// provided, even if the security verification detected major violations.  Make sure you check
        ///  <see cref="SecurityInformation"/> is the data is valid and can be trusted or not.
        /// </para>
        /// <para>
        /// The property is always a stream, but can eighter be a MemoryStream or a Temporaly FileStream, depending
        /// on the Unseal method that was invoked.  The FileStream does clean up the temporaly file on closing.
        /// </para>
        /// </value>
        public Stream UnsealedData
        {
            get
            {
                return unsealedData;
            }
            internal set
            {
                unsealedData = value;
            }
        }

        /// <summary>
        /// The issuer/sender of the message.
        /// </summary>
        /// <value>
        /// <para>
        /// The application is supposed to verify that the sender is actualy
        /// allowed to send this type of messages, the libray only validate
        /// that the sender information can be used (=trusted) or not.  The rules for validation
        /// is outside the scope of this project, as is the definition of the list
        /// of allowed senders.
        /// </para>
        /// <para>
        /// The same information can be retrieved from the <see cref="SecurityInformation"/> property.
        /// </para>
        /// </value>
        public X509Certificate2 Sender
        {
            get
            {
                return securityInformation.OuterSignature.Subject.Certificate;
            }
        }

        /// <summary>
        /// The results of the security checks.
        /// </summary>
        /// <value>
        /// This propery must be used to check if the data of the <see cref="UnsealedData"/> is
        /// valid and can be trusted is not.  You should not accept any messages that have a
        /// validation status different from <see cref="ValidationStatus.Valid"/> or a truststatus
        /// different from <see cref="TrustStatus.Full"/>.
        /// </value>
        public UnsealSecurityInformation SecurityInformation
        {
            get
            {
                return securityInformation;
            }
            internal set
            {
                securityInformation = value;
            }
        }


    }
}
