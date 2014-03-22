using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    public interface ITimemarkProvider
    {
        DateTime GetTimemark(X509Certificate2 sender, DateTime signingTime, byte[] signatureValue);
    }
}
