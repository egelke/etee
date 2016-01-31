using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class ProxyRsaKeyParameters : RsaKeyParameters
    {
        RSACryptoServiceProvider proxy;

        public ProxyRsaKeyParameters(RSACryptoServiceProvider proxy)
            : base(false, 
                new Math.BigInteger(1, proxy.ExportParameters(false).Modulus),
                new Math.BigInteger(1, proxy.ExportParameters(false).Exponent))
        {
            this.proxy = proxy;
        }

        public RSACryptoServiceProvider Proxy
        {
            get
            {
                return this.proxy;
            }
        }
    }
}
