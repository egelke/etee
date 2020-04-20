using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class HashAlgorithmProxy : Stream
    {
        private static readonly byte[] finalBlock = new byte[0];

        private readonly HashAlgorithm proxy;

        public HashAlgorithmProxy(HashAlgorithm target)
        {
            proxy = target;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => proxy.HashSize;

        public override long Position { get => throw new InvalidOperationException(); set => throw new InvalidOperationException(); }

        public override void Flush()
        {
            //NO-OP
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new InvalidOperationException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new InvalidOperationException();
        }

        public override void SetLength(long value)
        {
            throw new InvalidOperationException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            proxy.TransformBlock(buffer, offset, count, null, 0);
        }

        public override void Close()
        {
            proxy.TransformFinalBlock(finalBlock, 0, 0);
            base.Close();
        }
    }
}
