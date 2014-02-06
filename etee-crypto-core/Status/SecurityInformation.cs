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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Collections.ObjectModel;
using Egelke.EHealth.Etee.Crypto.Utils;

namespace Egelke.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// Security information of encrypted blocks, based for signed blocks.
    /// </summary>
    public class SecurityInformation : SecurityResult<SecurityViolation>
    {
        private CertificateSecurityInformation subject;

        /// <summary>
        /// Information about the issuer/sender (signature) or recipient (decryption).
        /// </summary>
        public CertificateSecurityInformation Subject
        {
            get
            {
                return subject;
            }
            internal set
            {
                subject = value;
            }
        }

        /// <summary>
        /// Detailed list of all the security violations for this object.
        /// </summary>
        /// <seealso cref="SecurityViolation"/>
        public override ReadOnlyCollection<SecurityViolation> SecurityViolations
        {
            get
            {
                UniqueCollection<SecurityViolation> violations = new UniqueCollection<SecurityViolation>(base.securityViolations);
                if (this.Subject != null)
                {
                    //Add the cumuldated result of the parent parents
                    switch (this.Subject.TrustStatus)
                    {
                        case TrustStatus.Unsure:
                            violations.Add(SecurityViolation.SubjectTrustUnknown);
                            break;
                        case TrustStatus.None:
                            violations.Add(SecurityViolation.UntrustedSubject);
                            break;
                        default:
                            break;
                    }
                    //Add the result of the parent
                    switch (this.Subject.ValidationStatus)
                    {
                        case ValidationStatus.Invalid:
                            violations.Add(SecurityViolation.UntrustedSubject);
                            break;
                        case ValidationStatus.Unsure:
                            violations.Add(SecurityViolation.SubjectTrustUnknown);
                            break;
                        default:
                            break;
                    }
                    //Remove less specific violations
                    if (violations.Contains(SecurityViolation.UntrustedSubject))
                    {
                        violations.Remove(SecurityViolation.SubjectTrustUnknown);
                    }
                }
                return new ReadOnlyCollection<SecurityViolation>(violations);
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
            builder.AppendLine("Subject: ");
            if (Subject != null)
            {
                builder.Append(Subject.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Provided>>");
            }

            return builder.ToString();
        }
    }
}
