/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// Security information of signed blocks
    /// </summary>
    public class SignatureSecurityInformation : SecurityInformation
    {
        /// <summary>
        /// The (UTC) time the message was sealed on.
        /// </summary>
        public DateTime? SigningTime { get; internal set; }

        /// <summary>
        /// The value of the signature (for Time Marker Authority)
        /// </summary>
        public byte[] SignatureValue { get; internal set; }

        /// <summary>
        /// The certificate of the signer.
        /// </summary>
        public X509Certificate2 Signer
        {
            get
            {
                return this.Subject.Certificate;
            }
        }

        /// <summary>
        /// The (UTC) time the timestamp should be renewed (if applicable).
        /// </summary>
        public DateTime? TimestampRenewalTime { get; internal set; }
        
        /// <summary>
        /// Used in the ToString method
        /// </summary>
        /// <param name="level">The identation level</param>
        /// <returns>The string representation of the object</returns>
        internal protected override string ToString(int level)
        {
            if (level == int.MaxValue) throw new ArgumentOutOfRangeException("level");

            String lv1 = new string('\t', level);
            String lv2 = new string('\t', level + 1);
            StringBuilder builder = new StringBuilder();

            builder.Append(lv1);
            builder.Append("Signing Time: ");
            if (SigningTime != null)
            {
                builder.Append(SigningTime);
                builder.AppendLine();
            }
            else
            {
                builder.AppendLine("<<Not Provided>>");
            }
            builder.Append(lv1);
            builder.Append("Timestamp Renewal Time: ");
            if (TimestampRenewalTime != null)
            {
                builder.Append(TimestampRenewalTime);
                builder.AppendLine();
            }
            else
            {
                builder.AppendLine("<<Not Provided>>");
            }
            builder.Append(lv1);
            builder.Append("Signature Value: ");
            if (SignatureValue != null)
            {
                builder.Append(Convert.ToBase64String(SignatureValue));
                builder.AppendLine();
            }
            else
            {
                builder.AppendLine("<<Not Provided>>");
            }
            builder.Append(base.ToString(level));

            return builder.ToString();
        }
    }
}
