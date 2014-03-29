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
using System.Text;
using System.Collections.ObjectModel;
using System.Reflection;
using Egelke.EHealth.Etee.Crypto.Utils;

namespace Egelke.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// Base class for security violation data.
    /// </summary>
    /// <typeparam name="TViolation">The enum of possible violations</typeparam>
    public abstract class SecurityResult<TViolation>
        where TViolation : struct
    {
        internal IList<TViolation> securityViolations = new UniqueCollection<TViolation>();

        /// <summary>
        /// Indicates if the content can be trusted.
        /// </summary>
        public virtual ValidationStatus ValidationStatus
        {
            get
            {
                ValidationStatus status = ValidationStatus.Valid;
                foreach (TViolation violation in SecurityViolations)
                {
                    ValidationStatus newStatus = StatusHelper<TViolation>.GetValidationStatus(violation);
                    if (status < newStatus) status = newStatus;
                }
                return status;
            }
        }

        /// <summary>
        /// Indicates if the sender can be confirmed.
        /// </summary>
        public virtual TrustStatus TrustStatus
        {
            get
            {
                TrustStatus status = TrustStatus.Full;
                foreach (TViolation violation in SecurityViolations)
                {
                    TrustStatus newStatus = StatusHelper<TViolation>.GetTrustStatus(violation);
                    if (status < newStatus) status = newStatus;
                }
                return status;
            }
        }

        /// <summary>
        /// Detailed list of all the security violations for this object.
        /// </summary>
        public virtual ReadOnlyCollection<TViolation> SecurityViolations
        {
            get
            {
                return new ReadOnlyCollection<TViolation>(securityViolations);
            }
        }

        /// <summary>
        /// Detailed printout of the object.
        /// </summary>
        /// <returns>String representation of the instance</returns>
        public override string ToString()
        {
            return ToString(0);
        }

        /// <summary>
        /// Detail printout to incopreate in the parent printout.
        /// </summary>
        /// <param name="level">The number of parent</param>
        /// <returns>String representation of the instance</returns>
        internal protected virtual String ToString(int level)
        {
            if (level == int.MaxValue) throw new ArgumentOutOfRangeException("level");

            String lv1 = new string('\t', level);
            String lv2 = new string('\t', level + 1);

            StringBuilder builder = new StringBuilder();
            builder.Append(lv1);
            builder.Append("Validation Status: ");
            builder.AppendLine(ValidationStatus.ToString());
            builder.Append(lv1);
            builder.Append("Trust Status: ");
            builder.AppendLine(TrustStatus.ToString());
            builder.Append(lv1);
            builder.AppendLine("Security Violations: ");
            if (SecurityViolations.Count == 0)
            {
                builder.Append(lv2);
                builder.AppendLine("<<None>>");
            }
            else
            {
                foreach (TViolation violation in SecurityViolations)
                {
                    builder.Append(lv2);
                    builder.AppendLine(violation.ToString());
                }
            }
            return builder.ToString();
        }
    }
}
