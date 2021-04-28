using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.Wcf.Client
{
    public class CustomSecurityRequestChannel : IRequestChannel
    {

        public CustomSecurityRequestChannel(IRequestChannel innerChannel, EndpointAddress to, Uri via)
        {
            _innerChannel = innerChannel;
            RemoteAddress = to;
            Via = via;
        }

        private IRequestChannel _innerChannel;

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
            return _innerChannel.Request(message);
        }

        public Message Request(Message message, TimeSpan timeout)
        {
            return _innerChannel.Request(message, timeout);
        }

        public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(message, callback, state);
        }

        public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(message, timeout, callback, state);
        }

        public Message EndRequest(IAsyncResult result)
        {
            return _innerChannel.EndRequest(result);
        }
    }
}
