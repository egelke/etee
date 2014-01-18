using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Library
{
    public interface ITransport
    {
        /// <summary>
        /// Override with the required protocol to send the provide (encrypted) request and receive the (encrypted) response.
        /// </summary>
        /// <remarks>
        /// This should only do the physical transfer, the encryption is already done (if needed) and the decryption will be done if needed by the caller.
        /// In case the repsonse is encrypted, the content should be the encrypted message and the content key id should be complete if applicable, the rest should be empty.
        /// </remarks>
        /// <param name="letter">The information to be transfered or needed for the transfer</param>
        /// <returns>Returns the response, if any.  If the reponse was encrypted, so is the letters content</returns>
        Task<Letter> TransferAsync(Letter letter);
    }
}
