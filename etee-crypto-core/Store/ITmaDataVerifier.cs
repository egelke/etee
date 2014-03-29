using Egelke.EHealth.Etee.Crypto.Status;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// Message verifier for time-mark authorities.
    /// </summary>
    public interface ITmaDataVerifier
    {
        /// <summary>
        /// Verifies the provided message on the provided date-time and returns the time-mark key.
        /// </summary>
        /// <remarks>
        /// Has an output parameter that will provide the time-mark key.  As a time-mark authority
        /// you are supposed use this key for the audit trail used for time-marking.  It must also
        /// be possibel to lookup the time-mark of the message via this key.
        /// </remarks>
        /// <seealso cref="IDataVerifier.Verify(Stream)"/>
        /// <param name="sealedData">The message to verify</param>
        /// <param name="date">The validate date of the message (normally reception date)</param>
        /// <param name="timemarkKey">The time-mark key to be linked to the message</param>
        /// <returns>The result and additional information about the authentication part of the message</returns>
        SignatureSecurityInformation Verify(Stream sealedData, DateTime date, out TimemarkKey timemarkKey);
    }
}
