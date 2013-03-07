using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;

namespace Egelke.EHealth.Client.EhBox
{
    public class EhBoxRecipient : KnownRecipient
    {

        public String Quality
        {
            get
            {
                return (String) this["Quality"];
            }
            set
            {
                this["Quality"] = value;
            }
        }

        public EhBoxRecipient(String type, String id, String quality)
            : base(type, id)
        {
            this["Quality"] = quality;
        }

        public EhBoxRecipient(String type, String id, String quality, String application)
            : base(type, id, application)
        {
            this["Quality"] = quality;
        }
    }
}
