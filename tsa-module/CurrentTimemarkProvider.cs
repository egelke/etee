using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Time-mark provider that always returns the current time.
    /// </summary>
    /// <remarks>
    /// Should only be used for testing purposes.
    /// </remarks>
    public class CurrentTimemarkProvider : ITimemarkProvider
    {
        public DateTime GetTimemark(System.Security.Cryptography.X509Certificates.X509Certificate2 sender, DateTime signingTime, byte[] signatureValue)
        {
            return DateTime.UtcNow;
        }
    }
}
