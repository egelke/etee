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
using System.Linq;
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
        public DateTime? SealedOn { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="level"></param>
        /// <returns></returns>
        internal protected override string ToString(int level)
        {
            if (level == int.MaxValue) throw new ArgumentOutOfRangeException("level");

            String lv1 = new string('\t', level);
            String lv2 = new string('\t', level + 1);
            StringBuilder builder = new StringBuilder();

            builder.Append(lv1);
            builder.Append("Sealed On: ");
            if (SealedOn != null)
            {
                builder.Append(SealedOn);
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
