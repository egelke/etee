using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace library_core_tests
{
    public class Config
    {
        static public Config Instance { get; private set; }

        static Config()
        {
            Instance = new Config();
        }

        IConfiguration configuration;

        public string Thumbprint => configuration.GetValue<string>("thumbprint");



        public X509Certificate2 Certificate
        {
            get
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadOnly);
                    return store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, false)[0];
                }
            }
        }

        public Config()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
            configuration = builder.Build();
        }
    }
}
