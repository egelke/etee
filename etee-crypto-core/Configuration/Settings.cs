using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    /// <summary>
    /// Global settings class of the library.
    /// </summary>
    public class Settings
    {
        private static Settings defaultInstance = new Settings();

        /// <summary>
        /// The default instance of the settings class, always use this.
        /// </summary>
        public static Settings Default
        {
            get
            {
                return defaultInstance;
            }
        }

        /// <summary>
        /// Indicates if the library should attempt to reteive OCSP and CRL information.
        /// </summary>
        /// <value>
        /// <para>
        /// The default value is <c>false</c>.
        /// </para>
        /// <para>
        /// This can be overridden with sealer and unslear at instance level.
        /// </para>
        /// </value>
        public bool Offline { get;  set; }

        /// <summary>
        /// Indicated how long a message may be sealed before the sealing time becomes invalid.
        /// </summary>
        /// <value>
        /// <para>
        /// The default value is 10 minutes.
        /// </para>
        /// <para>
        /// This defined the time that is allowed between the (indicated) sealing and the unsealing (validation).
        /// This value should be kept as small as possible and should never exceed more then a few hours.  The only
        /// exception is when the message comes from an internal (secure) storage and isn't just received by the
        /// sender or a 3rd party.
        /// </para>
        /// </value>
        public TimeSpan TrustPeriod { get; set; }

        private Settings() 
        {
            Offline = false;
            TrustPeriod = new TimeSpan(0, 15, 0);
        }
    }
}
