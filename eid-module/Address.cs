using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    public class Address
    {
        //internal Address Parse(Map<int, byte[]

        private String streetAndNumber;

        private String zip;

        private String municipality;

        public String StreetAndNumber
        {
            get
            {
                return streetAndNumber;
            }
        }

        public String Zip
        {
            get
            {
                return zip;
            }
        }

        public String Municipality
        {
            get
            {
                return municipality;
            }
        }
    }
}
