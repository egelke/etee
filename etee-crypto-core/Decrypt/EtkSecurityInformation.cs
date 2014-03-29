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
using Siemens.EHealth.Etee.Crypto.Utils;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Etee.Crypto.Decrypt
{
    /// <summary>
    /// Security information of Encryption Tokens.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Encryption Tokens or ETKs are kept in the ETK-depot and can be retreived freely.
    /// </para>
    /// <para>
    /// The ValidationStatus applies on the token, since in this case it is content.  The TrustStatus
    /// applies on the eHealth signature of the cms-message.
    /// </para>
    /// <para>
    /// For a detailed but still comprehensible representation of the instance,
    /// use the ToString method.  In general there is quite
    /// a lot of information, so a (tab aware) text viewer is advised.
    /// </para>
    /// </remarks>
    public class EtkSecurityInformation : SecurityResult<EtkSecurityViolation>
    {
        private SecurityInformation signature;

        private CertificateSecurityInformation encryptionToken;

        /// <summary>
        /// The verification information of the signature that was placed by the ETK-Depot.
        /// </summary>
        /// <value>
        /// The ETK is a signed message, normaly signed by eHealth.  The result of the
        /// signature validation can be found here.
        /// </value>
        public SecurityInformation Signature
        {
            get
            {
                return signature;
            }
            internal set
            {
                signature = value;
            }
        }

        /// <summary>
        /// The verification information of the encryption token.
        /// </summary>
        /// <value>
        /// <para>
        /// The ETK contains 2 certficates of which only one party (person, organisation, ...)
        /// has the private keys.  The authentication certificate can be used for signing only,
        /// the encryption certificate for encryption only.  The encryption certificate is
        /// "issued" (although not officialy) by the authentication certificate.
        /// </para>
        /// <para>
        /// The property provides you information, including validation, about the encryption certificate
        /// and its issuer (the authentication certificate).
        /// </para>
        /// </value>
        public CertificateSecurityInformation TokenInformation
        {
            get
            {
                return encryptionToken;
            }
            internal set
            {
                encryptionToken = value;
            }
        }

        /// <summary>
        /// The certificate of the party that created the ETK.
        /// </summary>
        /// <value>
        /// <para>
        /// The application is supposed to verify that the sender is actualy
        /// allowed to send this type of messages, the libray only validate
        /// that the sender information can be used or not.  The rules for validation
        /// is outside the scope of this project, as is the definition of the list
        /// of allowed senders.
        /// </para>
        /// <para>
        /// The same information can be retrieved from the <see cref="Signature"/> property.
        /// </para>
        /// </value>
        public X509Certificate2 Sender
        {
            get
            {
                return signature.Subject.Certificate;
            }
        }

        /// <summary>
        /// Detailed list of all the security violations for this object.
        /// </summary>
        /// <seealso cref="EtkSecurityViolation"/>
        public override System.Collections.ObjectModel.ReadOnlyCollection<EtkSecurityViolation> SecurityViolations
        {
            get
            {
                UniqueCollection<EtkSecurityViolation> violations = new UniqueCollection<EtkSecurityViolation>(base.securityViolations);
                if (this.TokenInformation != null)
                {
                    switch (this.TokenInformation.TrustStatus)
                    {
                        case Decrypt.TrustStatus.Unsure:
                            violations.Add(EtkSecurityViolation.TokenTrustUnknown);
                            break;
                        case Decrypt.TrustStatus.None:
                            violations.Add(EtkSecurityViolation.UntrustedToken);
                            break;
                        default:
                            break;
                    }
                    switch (this.TokenInformation.ValidationStatus)
                    {
                        case Decrypt.ValidationStatus.Invalid:
                            violations.Add(EtkSecurityViolation.InvalidToken);
                            break;
                        case Decrypt.ValidationStatus.Unsure:
                        case Decrypt.ValidationStatus.Unsupported:
                            violations.Add(EtkSecurityViolation.TokenValidationImpossible);
                            break;
                        default:
                            break;
                    }
                    if (violations.Contains(EtkSecurityViolation.UntrustedToken))
                    {
                        violations.Remove(EtkSecurityViolation.TokenTrustUnknown);
                    }
                    if (violations.Contains(EtkSecurityViolation.InvalidToken))
                    {
                        violations.Remove(EtkSecurityViolation.TokenValidationImpossible);
                    }
                }
                if (this.Signature != null)
                {
                    switch (this.Signature.TrustStatus)
                    {
                        case Decrypt.TrustStatus.Unsure:
                            violations.Add(EtkSecurityViolation.SenderTrustUnknown);
                            break;
                        case Decrypt.TrustStatus.None:
                            violations.Add(EtkSecurityViolation.UntrustedSender);
                            break;
                        default:
                            break;
                    }
                    switch (this.Signature.ValidationStatus)
                    {
                        case Decrypt.ValidationStatus.Invalid:
                            violations.Add(EtkSecurityViolation.InvalidToken);
                            break;
                        case Decrypt.ValidationStatus.Unsure:
                        case Decrypt.ValidationStatus.Unsupported:
                            violations.Add(EtkSecurityViolation.TokenTrustUnknown);
                            break;
                        default:
                            break;
                    }
                    if (violations.Contains(EtkSecurityViolation.UntrustedSender))
                    {
                        violations.Remove(EtkSecurityViolation.SenderTrustUnknown);
                    }
                }
                return new ReadOnlyCollection<EtkSecurityViolation>(violations);
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
            builder.AppendLine("Signature:");
            if (Signature != null)
            {
                builder.Append(Signature.ToString(level + 1));
            }
            else
            {
                builder.Append(lv2);
                builder.AppendLine("<<Not Available>>");
            }
            builder.Append(lv1);
            builder.AppendLine("Token Information:");
            if (TokenInformation != null)
            {
                builder.Append(TokenInformation.ToString(level + 1));
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
