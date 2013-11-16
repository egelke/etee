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
using System.Runtime.Serialization;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Exception indication the protected message can't be processed.
    /// </summary>
    /// <remarks>
    /// When a protected message is not compliant in a way that it is impossible to
    /// process it, an InvalidMessageException is thrown.
    /// </remarks>
    [Serializable]
    public class InvalidMessageException : Exception
    {

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors")]
        internal InvalidMessageException()
            : base()
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors")]
        internal InvalidMessageException(String msg)
            : base(msg)
        {

        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1032:ImplementStandardExceptionConstructors")]
        internal InvalidMessageException(String msg, Exception inner)
            : base(msg, inner)
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidMessageException"/> class with serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination. </param>
        protected InvalidMessageException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {

        }
    }
}
