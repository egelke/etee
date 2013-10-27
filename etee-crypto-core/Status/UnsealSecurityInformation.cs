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
    /// Information about the security checks while unsealing an message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Groups information about the outer signature, inner signature and
    /// encryption/decryption.  There are no specific checks/violations at 
    /// this level.
    /// </para>
    /// <para>
    /// For a detailed but still comprehensible representation of the instance,
    /// use the ToString method.  In general there is quite
    /// a lot of information, so a (tab aware) text viewer is advised.
    /// </para>
    /// </remarks>
    public class UnsealSecurityInformation : SecurityResult<UnsealSecurityViolation>
    {
        private DateTime? sealedOn;

        private SecurityInformation outerSignature;

        private SecurityInformation encryption;

        private SecurityInformation innerSignature;

        /// <summary>
        /// Detailed list of all the security violations for this object.
        /// </summary>
        /// <seealso cref="UnsealSecurityViolation"/>
        public override System.Collections.ObjectModel.ReadOnlyCollection<UnsealSecurityViolation> SecurityViolations
        {
            get
            {
                UniqueCollection<UnsealSecurityViolation> violations = new UniqueCollection<UnsealSecurityViolation>(base.securityViolations);
                if (this.OuterSignature != null)
                {
                    switch (this.OuterSignature.TrustStatus)
                    {
                        case TrustStatus.Unsure:
                            violations.Add(UnsealSecurityViolation.SenderTrustUnknown);
                            break;
                        case TrustStatus.None:
                            violations.Add(UnsealSecurityViolation.UntrustedSender);
                            break;
                        default:
                            break;
                    }
                    switch (this.OuterSignature.ValidationStatus)
                    {
                        case ValidationStatus.Invalid:
                            violations.Add(UnsealSecurityViolation.InvalidData);
                            break;
                        case ValidationStatus.Unsure:
                            throw new InvalidOperationException("The signature validation status should not be unsure");
                            break;
                        default:
                            break;
                    }
                }
                if (this.Encryption != null)
                {
                    switch (this.Encryption.TrustStatus)
                    {
                        case TrustStatus.Unsure:
                            //since we don't do many checks, we are pritty sure
                            throw new InvalidOperationException("The encryption trust status should not be unsure");
                        case TrustStatus.None:
                            violations.Add(UnsealSecurityViolation.UntrustedRecipient);
                            break;
                        default:
                            break;
                    }
                    switch (this.Encryption.ValidationStatus)
                    {
                        case ValidationStatus.Invalid:
                            violations.Add(UnsealSecurityViolation.InvalidData);
                            break;
                        case ValidationStatus.Unsure:
                            throw new InvalidOperationException("The encryption validation status should not be unsure");
                        default:
                            break;
                    }
                }
                if (this.InnerSignature != null)
                {
                    switch (this.InnerSignature.TrustStatus)
                    {
                        case TrustStatus.Unsure:
                            violations.Add(UnsealSecurityViolation.SenderTrustUnknown);
                            break;
                        case TrustStatus.None:
                            violations.Add(UnsealSecurityViolation.UntrustedSender);
                            break;
                        default:
                            break;
                    }
                    switch (this.InnerSignature.ValidationStatus)
                    {
                        case ValidationStatus.Invalid:
                            violations.Add(UnsealSecurityViolation.InvalidData);
                            break;
                        case ValidationStatus.Unsure:
                            throw new InvalidOperationException("The signature validation status should not be unsure");
                        default:
                            break;
                    }
                }
                if (violations.Contains(UnsealSecurityViolation.UntrustedSender))
                {
                    violations.Remove(UnsealSecurityViolation.SenderTrustUnknown);
                }
                return new ReadOnlyCollection<UnsealSecurityViolation>(violations);
            }
        }

        /// <summary>
        /// The time the message was sealed, if available.
        /// </summary>
        public DateTime? SealedOn
        {
            get
            {
                return sealedOn;
            }
            internal set
            {
                sealedOn = value;
            }
        }

        /// <summary>
        /// Security information about the outer signature.
        /// </summary>
        /// <value>
        /// Contains information if the encrypted messages was correctly
        /// signed an by who.
        /// </value>
        public SecurityInformation OuterSignature
        {
            get
            {
                return outerSignature;
            }
            internal set
            {
                outerSignature = value;
            }
        }

        /// <summary>
        /// Security information about the encryption/decryption.
        /// </summary>
        /// <value>
        /// Contains information if the encryption was done
        /// up to spec and the certificate that was used
        /// to decrypt.
        /// </value>
        public SecurityInformation Encryption
        {
            get
            {
                return encryption;
            }
            internal set
            {
                encryption = value;
            }
        }

        /// <summary>
        /// Security information about the inner signature.
        /// </summary>
        /// <value>
        /// Contains information if the was correctly signed
        /// and by who.
        /// </value>
        public SecurityInformation InnerSignature
        {
            get
            {
                return innerSignature;
            }
            internal set
            {
                innerSignature = value;
            }
        }

        /// <summary>
        /// Detail printout to incopreate in the parent printout.
        /// </summary>
        /// <param name="level">The number of parent</param>
        /// <returns>String representation of the instance</returns>
        protected internal override string ToString(int level)
        {
            if (level == int.MaxValue) throw new ArgumentOutOfRangeException("level");

            String lv1 = new string('\t', level);
            String lv2 = new string('\t', level + 1);
            StringBuilder builder = new StringBuilder();

            builder.Append(base.ToString(level));

            builder.Append(lv1);
            builder.Append("Sealed on: ");
            builder.AppendLine(SealedOn == null ? "<<Not Available>>" : SealedOn.ToString());

            builder.Append(lv1);
            builder.AppendLine("Outer Signature:");
            if (OuterSignature != null)
            {
                builder.Append(OuterSignature.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Available>>");
            }
            builder.Append(lv1);
            builder.AppendLine("Encryption:");
            if (Encryption != null)
            {
                builder.Append(Encryption.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Available>>");
            }

            builder.AppendLine("Inner Signature:");
            if (InnerSignature != null)
            {
                builder.Append(InnerSignature.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Available>>");
            }

            return builder.ToString();
        }
    }
}
