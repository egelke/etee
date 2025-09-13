using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace etee_crypto_xtests
{
    public class MyX509Certificate2 : X509Certificate2
    {
        public MyX509Certificate2(X509Certificate2 cert) : base(cert)
        {

        }

        public MyX509Certificate2(String file, String pwd) : base(file, pwd)
        {

        }

        public override string ToString()
        {
            String key = "unknown";
            if (this.GetRSAPublicKey() != null)
            {
                key = "rsa";
            }
            else if (this.GetECDsaPublicKey() != null)
            {
                key = "ec";
            }
            return this.GetNameInfo(X509NameType.SimpleName, false) + " (" + key + ")";
        }

    }
}
