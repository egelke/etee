/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Runtime.InteropServices;
using System.Text;

namespace Egelke.EHealth.Client.Sts
{
    /// <summary>
    /// Collection of Authentication Claims.
    /// </summary>
    public class AuthClaimSet : ICollection<Claim>, ICloneable
    {
        /// <summary>
        /// The dialect id for this type of claim set.
        /// </summary>
        public const string Dialect = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";

        private readonly IList<Claim> _claims;

        /// <summary>
        /// Number of claims in the set.
        /// </summary>
        public int Count => _claims.Count;

        /// <summary>
        /// Indicates if the claim set is read only or read/write.
        /// </summary>
        public bool IsReadOnly => _claims.IsReadOnly;

        /// <summary>
        /// Copy constuctor, create a read/write set.
        /// </summary>
        /// <param name="claims">claims to initialize with</param>
        public AuthClaimSet(params Claim[] claims)
        {
            _claims = new List<Claim>(claims);
            CheckRights();
        }

        /// <summary>
        /// Init constructor, uses the provided claims list directly.
        /// </summary>
        /// <param name="claims"></param>
        public AuthClaimSet(IList<Claim> claims)
        {
            _claims = claims;
            CheckRights();
        }

        private void CheckRights()
        {
            foreach (var claim in _claims)
            {
                if (!SupportedRight(claim)) throw new InvalidOperationException("Unsupported claim right: " + claim.Right);
            }
        }

        private bool SupportedRight(Claim claim)
        {
            return claim.Right == null || claim.Right == Dialect;
        }

        /// <summary>
        /// Converts the set to an enumerator.
        /// </summary>
        /// <returns>new enumerator</returns>
        public IEnumerator<Claim> GetEnumerator()
        {
            return _claims.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Add a claim to the set.
        /// </summary>
        /// <param name="item">The claim to add</param>
        public void Add(Claim item)
        {
            _claims.Add(item);
        }

        /// <summary>
        /// Clears all claims.
        /// </summary>
        public void Clear()
        {
            _claims.Clear();
        }

        /// <summary>
        /// Checks if a claim is already in the set.
        /// </summary>
        /// <param name="item">claim to check</param>
        /// <returns>true is the claim is already present</returns>
        public bool Contains(Claim item)
        {
            return _claims.Contains(item);
        }

        /// <summary>
        /// Copy the claims into an array
        /// </summary>
        /// <param name="array">array to copy too</param>
        /// <param name="arrayIndex">starting index into the array</param>
        public void CopyTo(Claim[] array, int arrayIndex)
        {
            _claims.CopyTo(array, arrayIndex);
        }

        /// <summary>
        /// Removes a claim from the set
        /// </summary>
        /// <param name="item">claim to remove</param>
        /// <returns>true if removed, false if not found</returns>
        public bool Remove(Claim item)
        {
            return _claims.Remove(item);
        }

        /// <summary>
        /// Creates a writable clone of the current set.
        /// </summary>
        /// <returns>a new instance</returns>
        public object Clone()
        {
            return new AuthClaimSet(new List<Claim>(_claims));
        }
    }
}
