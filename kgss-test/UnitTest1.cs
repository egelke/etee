using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using kgss_test.EHealth;

namespace kgss_test
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            GetKeyRequest request = new GetKeyRequest();
            request.SealedKeyRequest = new SealedContentType();
            //TODO:take sealed content

            KgssPortTypeClient kgss = new KgssPortTypeClient("kgss-79021802145");
            GetKeyResponse response = kgss.GetKey(request);
        }
    }
}
