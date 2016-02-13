using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Store;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class WinX509CollectionStore : IX509Store
    {
        private X509Certificate2Collection win;
        private IList bc;

        public WinX509CollectionStore(X509Certificate2Collection collection)
        {
            win = collection;
            bc = new List<Org.BouncyCastle.X509.X509Certificate>();
            for (int i = 0; i < collection.Count; i++)
            {
                bc.Add(DotNetUtilities.FromX509Certificate(collection[i]));
            }
        }

        public ICollection GetMatches(IX509Selector selector)
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
