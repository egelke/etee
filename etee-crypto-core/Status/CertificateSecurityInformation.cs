/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Collections.ObjectModel;
using Siemens.EHealth.Etee.Crypto.Utils;

namespace Siemens.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// Security information of certificates.
    /// </summary>
    public class CertificateSecurityInformation : SecurityResult<CertSecurityViolation>
    {
        private X509Certificate2 certificate;

        private CertificateSecurityInformation issuer;

        /// <summary>
        /// The certificate on which the checks where executed.
        /// </summary>
        public X509Certificate2 Certificate
        {
            get
            {
                return certificate;
            }
            internal set
            {
                certificate = value;
            }
        }

        /// <summary>
        /// The security information of the issuer.
        /// </summary>
        public CertificateSecurityInformation IssuerInfo
        {
            get
            {
                return issuer;
            }
            internal set
            {
                issuer = value;
            }
        }

        /// <summary>
        /// Detailed list of all the security violations for this object.
        /// </summary>
        /// <seealso cref="CertSecurityViolation"/>
        public override ReadOnlyCollection<CertSecurityViolation> SecurityViolations
        {
            get
            {
                UniqueCollection<CertSecurityViolation> violations = new UniqueCollection<CertSecurityViolation>(base.securityViolations);
                if (this.IssuerInfo != null)
                {
                    //Add the cumuldated result of the parent parents
                    switch (this.IssuerInfo.TrustStatus)
                    {
                        case TrustStatus.Unsure:
                            violations.Add(CertSecurityViolation.IssuerTrustUnknown);
                            break;
                        case TrustStatus.None:
                            violations.Add(CertSecurityViolation.UntrustedIssuer);
                            break;
                        default:
                            break;
                    }
                    //Add the result of the parent
                    switch (this.IssuerInfo.ValidationStatus)
                    {
                        case ValidationStatus.Invalid:
                            violations.Add(CertSecurityViolation.UntrustedIssuer);
                            break;
                        case ValidationStatus.Unsure:
                        case ValidationStatus.Unsupported:
                            violations.Add(CertSecurityViolation.IssuerTrustUnknown);
                            break;
                        default:
                            break;
                    }
                    //Remove less specific violations
                    if (violations.Contains(CertSecurityViolation.UntrustedIssuer))
                    {
                        violations.Remove(CertSecurityViolation.IssuerTrustUnknown);
                    }
                }
                return new ReadOnlyCollection<CertSecurityViolation>(violations);
            }
        }

        /// <summary>
        /// Detail printout to incopreate in the parent printout.
        /// </summary>
        /// <param name="level">The number of parent</param>
        /// <returns>String representation of the instance</returns>
        internal protected override string ToString(int level)
        {
            if (level == int.MaxValue) throw new ArgumentOutOfRangeException("level");

            String lv1 = new string('\t', level);
            String lv2 = new string('\t', level + 1);
            StringBuilder builder = new StringBuilder();

            builder.Append(base.ToString(level));
            builder.Append(lv1);
            builder.AppendLine("Certificate:");
            if (Certificate != null)
            {
                builder.Append(lv2);
                builder.AppendLine(certificate.ToString(false).Replace("\n", "\n"+ lv2));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Provided>>");
            }

            builder.Append(lv1);
            builder.AppendLine("Issuer Info:");
            if (IssuerInfo != null)
            {
                builder.Append(IssuerInfo.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Unknown or Root>>");
            }

            return builder.ToString();
        }
    }
}
