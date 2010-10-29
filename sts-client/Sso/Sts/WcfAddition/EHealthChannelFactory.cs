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
    public class EHealthChannelFactory<TChannel> : ChannelFactoryBase<TChannel>
    {
        IChannelFactory<TChannel> innerChannelFactory;

        public EHealthChannelFactory(BindingContext context)
        {
            this.innerChannelFactory = context.BuildInnerChannelFactory<TChannel>();
            if (this.innerChannelFactory == null)
            {
                throw new InvalidOperationException("InterceptingChannelFactory requires an inner IChannelFactory.");
            }
        }

        protected override TChannel OnCreateChannel(System.ServiceModel.EndpointAddress address, Uri via)
        {
            TChannel innerChannel = this.innerChannelFactory.CreateChannel(address, via);
            if (typeof(TChannel) == typeof(IOutputChannel))
            {
                return (TChannel)(object)new EHealthOutputChannel(this, (IOutputChannel)innerChannel);
            }
            else if (typeof(TChannel) == typeof(IRequestChannel))
            {
                return (TChannel)(object)new EHealthRequestChannel(this, (IRequestChannel)innerChannel);
            }
            throw new InvalidOperationException();
        }

        protected override IAsyncResult OnBeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return this.innerChannelFactory.BeginOpen(timeout, callback, state);
        }

        protected override void OnEndOpen(IAsyncResult result)
        {
            this.innerChannelFactory.EndOpen(result);
        }

        protected override void OnOpen(TimeSpan timeout)
        {
            this.innerChannelFactory.Open(timeout);
        }
    }
}
