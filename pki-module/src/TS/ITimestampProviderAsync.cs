using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    interface ITimestampProviderAsync : ITimestampProvider
    {

        /// <summary>
        /// Create a new timestap
        /// </summary>
        /// <seealso cref="ITimestampProvider#GetTimestampFromDocumentHash"/>
        /// <param name="hash">The hash of the document that must be timestamped</param>
        /// <param name="digestMethod">The hasm method that was used, in XML-DSIG (and related) format e.g. <literal>http://www.w3.org/2001/04/xmlenc#sha256</literal></param>
        /// <returns>a binary version of a RFC3161 compliant timestamp token (not the response) valid for the provided hash</returns>
        Task<byte[]> GetTimestampFromDocumentHashAsync(byte[] hash, String digestMethod);
    }
}
