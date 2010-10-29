/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Channels;

namespace Siemens.EHealth.Client.Sso.Sts.WcfAddition
{
    public class EHealthOutputChannel : EHealthChannel<IOutputChannel>, IOutputChannel
    {
        public EHealthOutputChannel(ChannelManagerBase manager, IOutputChannel innerChannel)
            : base(manager, innerChannel)
        {

        }


        #region IOutputChannel Members

        public IAsyncResult BeginSend(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return this.innerChannel.BeginSend(new EHealthMessage(message), timeout, callback, state);
        }

        public IAsyncResult BeginSend(Message message, AsyncCallback callback, object state)
        {
            return BeginSend(message, DefaultSendTimeout, callback, state);
        }

        public void EndSend(IAsyncResult result)
        {
            this.innerChannel.EndSend(result);
        }

        public System.ServiceModel.EndpointAddress RemoteAddress
        {
            get { return this.innerChannel.RemoteAddress; }
        }

        public void Send(Message message, TimeSpan timeout)
        {
            Send(new EHealthMessage( message), DefaultSendTimeout);
        }

        public void Send(Message message)
        {
            this.innerChannel.Send(message);
        }

        public Uri Via
        {
            get { return this.innerChannel.Via; }
        }

        #endregion
    }
}
