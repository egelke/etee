using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    public class Settings
    {
        private static Settings defaultInstance = new Settings();

        public static Settings Default
        {
            get
            {
                return defaultInstance;
            }
        }

        public bool Offline { get;  set; }

        private Settings() 
        {
            Offline = false;
        }
    }
}
