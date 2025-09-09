/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Sts
{
    /// <summary>
    /// Generic service contact to send/receive any message with any action.
    /// </summary>
    [ServiceContract]
    public interface IGenericPortType
    {
        /// <summary>
        /// Send and receive any message sync.
        /// </summary>
        /// <param name="request">The request</param>
        /// <returns>The response</returns>
        [OperationContract(Action = "*", ReplyAction = "*")]
        Message Send(Message request);

        /// <summary>
        /// Send and receive any message async.
        /// </summary>
        /// <remarks>
        /// Async refers to the call type, i.e. using promises.  
        /// This has nothing to do with the MyCareNet GenAsync interface.
        /// </remarks>
        /// <param name="request">The request</param>
        /// <returns>The response in an async task</returns>
        [OperationContract(Action = "*", ReplyAction = "*")]
        Task<Message> SendAsync(Message request);

        /// <summary>
        /// Send and forget a message.
        /// </summary>
        /// <param name="request">The request</param>
        [OperationContract(IsOneWay = true, Action = "*")]
        void SendOneWay(Message request);
    }
}
