using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal static class X509CertStoreSelectorExtention
    {

        public static byte[] ExtractSignerId(this SignerID selector)
        {
            //In case of SignerID it seems to be the encoded Octet String (bug?)
            return Asn1OctetString.GetInstance(DerOctetString.FromByteArray(selector.SubjectKeyIdentifier)).GetOctets();
        }

        public static byte[] ExtractSignerId(this RecipientID selector)
        {
            //In case of a Recipient it seems to be raw
            return selector.SubjectKeyIdentifier;
        }
    }
}
