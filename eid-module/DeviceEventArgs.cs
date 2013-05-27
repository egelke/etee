using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.Fedict.Eid
{
    public class DeviceEventArgs : EventArgs
    {
        private String deviceName;
        private DeviceState previousState;
        private DeviceState newState;

        public String DeviceName
        {
            get
            {
                return deviceName;
            }
        }

        public DeviceState PreviousState
        {
            get
            {
                return previousState;
            }
        }

        public DeviceState NewState
        {
            get
            {
                return newState;
            }
        }

        internal DeviceEventArgs(String deviceName, DeviceState previousState, DeviceState newState)
        {
            this.deviceName = deviceName;
            this.previousState = previousState;
            this.newState = newState;
        }

    }
}
