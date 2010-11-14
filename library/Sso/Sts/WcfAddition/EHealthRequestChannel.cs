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
    public class EHealthRequestChannel : EHealthChannel<IRequestChannel>, IRequestChannel
    {
        public EHealthRequestChannel(ChannelManagerBase manager, IRequestChannel innerChannel)
            : base(manager, innerChannel)
        {

        }

        #region IRequestChannel Members

        public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return innerChannel.BeginRequest(new EHealthMessage(message), timeout, callback, state);
        }

        public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
        {
            return BeginRequest(message, DefaultSendTimeout, callback, state);
        }

        public Message EndRequest(IAsyncResult result)
        {
            return innerChannel.EndRequest(result);
        }

        public System.ServiceModel.EndpointAddress RemoteAddress
        {
            get { return innerChannel.RemoteAddress; }
        }

        public Message Request(Message message, TimeSpan timeout)
        {
            return innerChannel.Request(new EHealthMessage(message));
        }

        public Message Request(Message message)
        {
            return Request(message, DefaultSendTimeout);
        }

        public Uri Via
        {
            get { return innerChannel.Via; }
        }

        #endregion
    }
}
