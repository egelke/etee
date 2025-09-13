using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class RootCAFicture
    {
        protected string CAFilePattern;

        protected Dictionary<string, string> CACerts = new Dictionary<string, string>();

        public X509Store Store { get; private set; }

        public Dictionary<string, bool> Verify()
        {
            Store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            try {
                Store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                return CACerts
                    .Select(e => new Tuple<String, bool>(e.Key, HasCert(e.Value)))
                    .ToDictionary(e => e.Item1, e => e.Item2, StringComparer.OrdinalIgnoreCase);
            }
            finally
            {
                Store?.Dispose(); //includes close
                Store = null;
            }
        }

        public void Install(params String[] cas)
        {
            Store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            try {
                Store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                CACerts
                    .Where(e => cas.Contains(e.Key, StringComparer.OrdinalIgnoreCase) && !HasCert(e.Value))
                    .Select(e => String.Format(CAFilePattern, e.Key))
                    .ToList()
                    .ForEach(f => 
                        Store.Add(new X509Certificate2(f))
                    );
            }
            finally
            {
                Store?.Dispose();
                Store = null;
            }
        }

        private bool HasCert(String thumbprint)
        {
            return Store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count >= 1;
        }
    }
}
