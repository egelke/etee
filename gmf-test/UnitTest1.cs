using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.Gmf;
using System.ServiceModel.Channels;
using Egelke.EHealth.Client.Builder;
using System.ServiceModel;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace gmf_test
{
    [TestClass]
    public class Doctor
    {


        [TestMethod]
        public void KmehrConsultConfigViaConfig()
        {
            X509Certificate2 auth = null; //TODO: select eID
            X509Certificate2 session = null; //TODO: select p12

            Binding sso = DoctorBuilder.CreateBinding("79021802145", "19997341001", new Uri("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService"));
            var proxy = new GlobalMedicalFileConsultationPortTypeClient(sso, new EndpointAddress("https://services-acpt.ehealth.fgov.be/GlobalMedicalFileConsultation/v1"));
            //DoctorBuilder.ApplyBehaviors(proxy, auth, Path.GetTempPath(), TimeSpan.FromHours(12));

        }
    }
}
