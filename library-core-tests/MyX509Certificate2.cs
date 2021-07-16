using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace library_core_tests
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
            return this.GetNameInfo(X509NameType.SimpleName, false);
        }

    }
}
