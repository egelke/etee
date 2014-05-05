using Egelke.EHealth.Client.Pki;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Gmf;
using System.ServiceModel.Channels;

namespace Egelke.EHealth.Client.Gmf
{
    public class DmfConsultClient
    {
        public static String SessionStorePath { get; set; }

        static DmfConsultClient()
        {
            SessionStorePath = Path.GetTempPath();
        }

        public GlobalMedicalFileConsultationPortTypeClient Proxy { get; set; }

        /*
        public DmfConsultClient(bool isTest, String ssin, String nihii11, )
        {
            Binding ssoBinding = DoctorBinding.
            this.Proxy = new GlobalMedicalFileConsultationPortTypeClient()
        }
        */

        public void Consult(string inputRef, CareReceiverIdType careReceiver, DateTime referenceDate, out ArchivingInfo archivingInfo)
        {
            archivingInfo = null;
            //Proxy.Consult()
        }
    }
}
