using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using BC = Org.BouncyCastle;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class CrlVerifier
    {
        private static TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

        public static bool Verify(IList<X509Crl> crls, DateTime on, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer, string location)
        {
            X509Crl resentCrl = null;
            foreach (X509Crl crl in crls)
            {
                if (crl.IssuerDN.Equals(issuer.SubjectDN) 
                    && (resentCrl == null || resentCrl.ThisUpdate < crl.ThisUpdate))
                {
                    resentCrl = crl;
                }
            }

            if (resentCrl == null) return false;

            Verify(resentCrl, on, cert, issuer, location);
            return true;
        }

        public static void Verify(X509Crl crl, DateTime on, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer, string location)
        {
            //check if the CRL is issued by the same certificate
            try
            {
                crl.Verify(issuer.GetPublicKey());
            }
            catch
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved CRL {0} has an invalid signature", location);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " isn't valid");
            }

            //check if the crl wasn't expired on the signing time
            if (crl.NextUpdate.Value.AddMinutes(-5.0) < on)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved CRL {0} is expired on {1}", location, crl.NextUpdate.Value);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " has no active CRL");
            }

            //check if the cert isn't revoked
            if (crl.IsRevoked(cert))
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved CRL {0} indicates cert is expired on {1}", location, crl.GetRevokedCertificate(cert.SerialNumber).RevocationDate);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " is revoked");
            }
        }
    }
}
