using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class BERootCAFicture : RootCAFicture
    {
        public BERootCAFicture()
        {
            CAFilePattern = @"files/belgiumr{0}.crt";
            CACerts.Add("ca1", "dfdfac8947bdf75264a9233ac10ee3d12833dacc");
            CACerts.Add("ca2", "51cca0710af7733d34acdc1945099f435c7fc59f");
            CACerts.Add("ca3", "fd6b835c99b99e6ff84fcd0e6266a3610786a717");
            CACerts.Add("ca4", "6b97f89956592a9b2010197527b0dc4ca5ac9be0");
            CACerts.Add("ca6", "98989feec16ad774615415e93a963ea3eef5fe4f");
        }
    }
}
