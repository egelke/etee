using System;
using System.Collections.Generic;
using System.Text;

namespace Egelke.EHealth.Client.Services
{
    public class ServiceException : ApplicationException
    {
        public string Code { get; }

        public ServiceException(string code) { 
            Code = code;
        }

        public ServiceException(string code, string message) : base(message)
        {
            Code = code;
        }

        public ServiceException(string code, string message, Exception innerException) : base(message, innerException) {
            Code = code;
        }
    }
}
