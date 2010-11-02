using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading;
using System.Diagnostics;

namespace Siemens.EHealth.Etee.Crypto.Utils
{
    internal class MemoryPipeStream : Stream
    {

        private class Block
        {
            public Block(int blockSize)
            {
                this.array = new byte[blockSize];
            }

            public byte[] array;

            public int offset;

            public int count;
        }

        private readonly Queue<WeakReference> cache = new Queue<WeakReference>();

        private readonly LinkedList<Block> buffer = new LinkedList<Block>();

        private int blockSize;

        private int maxBlockCount;

        private Semaphore readSemaphore;

        private Semaphore writeSemaphore;

        private ManualResetEvent flushEvent;

        private ManualResetEvent closeEvent;

        public MemoryPipeStream()
            : this(5*1024, 512)
        {

        }

        public MemoryPipeStream(int blockSize, int maxBlockCount)
        {
            this.blockSize = blockSize;
            this.maxBlockCount = maxBlockCount;
            this.readSemaphore = new Semaphore(0, maxBlockCount);
            this.writeSemaphore = new Semaphore(maxBlockCount, maxBlockCount);
            this.flushEvent = new ManualResetEvent(true);
            this.closeEvent = new ManualResetEvent(false);
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override void Flush()
        {
            flushEvent.WaitOne();
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get
            {
                //Depends who it reads (writer or reader) which is impossible to tell.
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override void Close()
        {
            base.Close();

            closeEvent.Set();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count == 0) throw new ArgumentException("count can't be 0", "count");

            //wait until there is data available or until the stream is closed.
            if (WaitHandle.WaitAny(new WaitHandle[] { readSemaphore, closeEvent }) == 1)
            {
                return 0;
            }

            int read = 0;
            do
            {
                read += readNonBlocking(buffer, offset + read, count - read);
            } while (read < count && readSemaphore.WaitOne(1)); //check if more data is needed and if (some) of it is available in the next 100 ms

            return read;
        }

        private int readNonBlocking(byte[] buffer, int offset, int count)
        {
            //Get the next block in a thread safe way
            Block block;
            lock (this)
                block = this.buffer.First.Value;            

            //Copy data to be returned or not
            int read = count < block.count ? count : block.count;
            Array.Copy(block.array, block.offset, buffer, offset, read);

            //Check to see if block if empty or not.
            if (read == block.count)
            {
                //Remove the block from queue in thread safe way
                lock (this)
                {
                    //Keep the block as weak reference in a cache.
                    this.cache.Enqueue(new WeakReference(block));

                    //remove it from the buffer
                    this.buffer.RemoveFirst();

                    //If needed, notify the flush.
                    if (this.buffer.Count == 0) this.flushEvent.Set();
                }

                //Signal the writer, both to the flush and write method.
                writeSemaphore.Release();
            }
            else
            {
                //update the offset & count
                block.offset += read;
                block.count -= read;

                //since we did not use up the block, we need to update update the readSemaphore
                //Little catch: The wait we are resetting occurs from the calling method.
                readSemaphore.Release();
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count == 0) return;

            while (count > 0)
            {
                //wait until there is space available
                if (WaitHandle.WaitAny(new WaitHandle[] {closeEvent, writeSemaphore}) == 0)
                {
                    throw new InvalidOperationException("Stream is closed");
                }

                //Get a free block, try cache fisrt.
                Block block = null;
                lock (this)
                {
                    while (block == null && cache.Count > 0)
                    {
                        block = (Block)this.cache.Dequeue().Target;
                    }
                }
                //check if "life" block found in cache
                if (block == null)
                {
                    //cache empty, so make a new one
                    block = new Block(blockSize);
                }
                //Init the block data
                block.offset = 0;
                block.count = 0;

                //Copy the bytes
                int writen = count > blockSize ? blockSize : count;
                Array.Copy(buffer, offset, block.array, block.offset, writen);
                block.count = writen;

                //Add the bytes to the buffer and make available
                lock (this)
                {
                    //The stream isn't flushed any more
                    this.flushEvent.Reset();
                    this.buffer.AddLast(block);
                }
                readSemaphore.Release();

                //make ready for next loop
                count -= writen;
                offset += writen;
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

       
    }
}
