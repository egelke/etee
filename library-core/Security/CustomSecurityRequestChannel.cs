using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Security
{
    public class CustomSecurityRequestChannel : IRequestChannel
    {
        private ILogger _logger;

        private IRequestChannel _innerChannel;

        public CustomSecurityRequestChannel(ILogger logger, IRequestChannel innerChannel, EndpointAddress to, Uri via)
        {
            _logger = logger;
            _innerChannel = innerChannel;
            RemoteAddress = to;
            Via = via;
        }

        public ClientCredentials ClientCredentials { get; set; }

        public SecurityVersion MessageSecurityVersion { get; set; }

        public SignParts SignParts { get; set; }

        public CustomSecurity Security { get; set; }

        public EndpointAddress RemoteAddress { get; }

        public Uri Via { get; }

        

        public T GetProperty<T>() where T : class
        {
            if (typeof(T) == typeof(IRequestChannel))
            {
                return (T)(object)this;
            }

            return _innerChannel.GetProperty<T>();
        }


        public void Open()
        {
            _innerChannel.Open();
        }

        public void Open(TimeSpan timeout)
        {
            _innerChannel.Open(timeout);
        }
        public IAsyncResult BeginOpen(AsyncCallback callback, object state)
        {
            return _innerChannel.BeginOpen(callback, state);
        }

        public IAsyncResult BeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginOpen(timeout, callback, state);
        }

        public void EndOpen(IAsyncResult result)
        {
            _innerChannel.EndOpen(result);
        }


        public void Close()
        {
            _innerChannel.Close();
        }

        public void Close(TimeSpan timeout)
        {
            _innerChannel.Close(timeout);
        }

        public IAsyncResult BeginClose(AsyncCallback callback, object state)
        {
            return _innerChannel.BeginClose(callback, state);
        }

        public IAsyncResult BeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginClose(timeout, callback, state);
        }

        public void EndClose(IAsyncResult result)
        {
            _innerChannel.EndClose(result);
        }

        public void Abort()
        {
            _innerChannel.Abort();
        }

        public CommunicationState State => _innerChannel.State;

        public event EventHandler Closed
        {
            add { _innerChannel.Closed += value; }
            remove { _innerChannel.Closed -= value; }
        }
        public event EventHandler Closing
        {
            add { _innerChannel.Closing += value; }
            remove { _innerChannel.Closing -= value; }
        }
        public event EventHandler Faulted
        {
            add { _innerChannel.Faulted += value; }
            remove { _innerChannel.Faulted -= value; }
        }
        public event EventHandler Opened
        {
            add { _innerChannel.Opened += value; }
            remove { _innerChannel.Opened -= value; }
        }
        public event EventHandler Opening
        {
            add { _innerChannel.Opening += value; }
            remove { _innerChannel.Opening -= value; }
        }

        public Message Request(Message message)
        {
            return Verify(_innerChannel.Request(Wrap(message)));
        }

        public Message Request(Message message, TimeSpan timeout)
        {
            return Verify(_innerChannel.Request(Wrap(message), timeout));
        }

        public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(Wrap(message), callback, state);
        }

        public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(Wrap(message), timeout, callback, state);
        }

        public Message EndRequest(IAsyncResult result)
        {
            return Verify(_innerChannel.EndRequest(result));
        }

        private Message Wrap(Message message)
        {
            return new CustomSecurityAppliedMessage(message, _logger)
            {
                ClientCredentials = this.ClientCredentials,
                MessageSecurityVersion = this.MessageSecurityVersion,
                SignParts = this.SignParts,
                RemoteAddress = this.RemoteAddress,
                Security = this.Security
            };
        }

        private Message Verify(Message message)
        {
            if (message != null)
            {
                var wss = WSS.Create(MessageSecurityVersion);
                int i = message.Headers.FindHeader("Security", wss.SecExtNs);
                if (i >= 0)
                {
                    MessageHeaderInfo sec = message.Headers[i];
                    XmlDictionaryReader headerReader = message.Headers.GetReaderAtHeader(i);

                    var doc = new XmlDocument();
                    var header = (XmlElement) doc.ReadNode(headerReader);

                    wss.VerifyResponse(header);

                    message.Headers.UnderstoodHeaders.Add(sec);
                }
                else
                {
                    //TODO::OK to have unsecure responses?
                }
            }
            return message;
        }
    }
}
