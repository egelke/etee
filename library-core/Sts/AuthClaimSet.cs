using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Runtime.InteropServices;
using System.Text;

namespace Egelke.EHealth.Client.Sts
{
    public class AuthClaimSet : IEnumerable<Claim>
    {
        private readonly IList<Claim> _claims;

        public readonly String Dialect = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";

        public AuthClaimSet(params Claim[] claims)
        {
            _claims = claims;
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
    }
}
