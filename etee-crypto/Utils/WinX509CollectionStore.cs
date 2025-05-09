using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using BC = Org.BouncyCastle.X509;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinX509CollectionStore
    {
        private X509Certificate2Collection win;
        private IList<BC::X509Certificate> bc;

        public WinX509CollectionStore(X509Certificate2Collection collection)
        {
            win = collection;
            bc = new List<BC::X509Certificate>();
            for (int i = 0; i < collection.Count; i++)
            {
                bc.Add(DotNetUtilities.FromX509Certificate(collection[i]));
            }
        }

        public IList GetMatches(ISelector<BC::X509Certificate> selector)
        {
            if (selector == null)
            {
                return win;
            }

            IList result = new ArrayList();
            for (int i = 0; i < win.Count; i++)
            {
                if (selector.Match(bc[i]))
                    result.Add(win[i]);
            }
            return result;
        }
    }
}
