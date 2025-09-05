using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Runtime.InteropServices;
using System.Text;

namespace Egelke.EHealth.Client.Sts
{
    public class AuthClaimSet : ICollection<Claim>, ICloneable
    {
        private readonly IList<Claim> _claims;

        public readonly String Dialect = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";

        public int Count => throw new NotImplementedException();

        public bool IsReadOnly => throw new NotImplementedException();

        public AuthClaimSet(params Claim[] claims)
        {
            _claims = new List<Claim>(claims);
            CheckRights();
        }

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

        public IEnumerator<Claim> GetEnumerator()
        {
            return _claims.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public void Add(Claim item)
        {
            _claims.Add(item);
        }

        public void Clear()
        {
            _claims.Clear();
        }

        public bool Contains(Claim item)
        {
            return _claims.Contains(item);
        }

        public void CopyTo(Claim[] array, int arrayIndex)
        {
            _claims.CopyTo(array, arrayIndex);
        }

        public bool Remove(Claim item)
        {
            return _claims.Remove(item);
        }

        public object Clone()
        {
            return new AuthClaimSet(new List<Claim>(_claims));
        }
    }
}
