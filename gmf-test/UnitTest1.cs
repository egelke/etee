using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.Dmf;

namespace gmf_test
{
    [TestClass]
    public class UnitTest1
    {


        [TestMethod]
        public void ConsultConfigViaConfig()
        {
            var proxy = new GlobalMedicalFileConsultationPortTypeClient();

        }

        [TestMethod]
        public void ConsultConfigViaConfig()
        {
            var proxy = new GlobalMedicalFileNotificationPortTypeClient();

        }
    }
}
