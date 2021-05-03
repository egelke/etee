using System;
using System.Collections.Generic;
using System.Text;

namespace Egelke.Wcf.Client.Helper
{
    public class WSS10 : WSS
    {
        public static string NS = 
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";

        public static string SECEXT_NS = 
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

        public static string UTILITY_NS = 
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        public static string TOKEN_PROFILE_X509_NS = 
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";

        public override string Ns => NS;

        public override string SecExtNs => SECEXT_NS;

        public override string UtilityNs => UTILITY_NS;

        public override string TokenPofileX509Ns => TOKEN_PROFILE_X509_NS;
    }
}
