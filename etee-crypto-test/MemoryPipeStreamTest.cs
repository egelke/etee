using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;
using Siemens.EHealth.Etee.Crypto.Utils;
using System.Threading.Tasks;

namespace Siemens.eHealth.ETEE.Crypto.Test
{
    [TestClass]
    public class MemoryPipeStreamTest
    {


        [TestMethod]
        public void NormalFlushClose()
        {
            Task<int> writer;
            Task<int> reader;

            MemoryPipeStream pipe = new MemoryPipeStream();
            writer = new Task<int>(this.NormalFlushCloseWriter, pipe);
            reader = new Task<int>(this.NormalReader, pipe);

            DateTime start = DateTime.Now;
            writer.Start();
            reader.Start();

            reader.Wait();
            DateTime stop = DateTime.Now;

            Double gb = ((double)writer.Result) / 1024.0 / 1024.0 / 1024.0;
            int s = (stop - start).Seconds;
            Assert.AreEqual(writer.Result, reader.Result);
            Assert.Inconclusive(String.Format("Transfer: {0} GB in {1} s; rate {2} MB/s", gb, s, (gb*1024)/s));
        }

        private int NormalFlushCloseWriter(object param)
        {

            int writeBytes = 0;
            Random rand = new Random();
            byte[] buffer = new byte[10*1024];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = byte.MaxValue;
            }

            MemoryPipeStream stream = (MemoryPipeStream)param;
            for (int i = 0; i < 1024*1024; i++)
            {
                int write = rand.Next(buffer.Length - 1) + 1;
                stream.Write(buffer, 0, write);
                writeBytes += write;
            }
            stream.Flush();
            stream.Close();
            return writeBytes;
        }

        private int NormalReader(object param)
        {
            int readBytes = 0;
            Random rand = new Random(DateTime.Now.Subtract(new TimeSpan(0, 1, 0)).Millisecond);
            byte[] buffer = new byte[10 * 1024];

            MemoryPipeStream stream = (MemoryPipeStream)param;
            int read = 0;
            do
            {
                read = stream.Read(buffer, 0, rand.Next(buffer.Length - 1) + 1);
                if (read != 0)
                {
                    Assert.AreEqual(byte.MaxValue, buffer[0]);
                    Assert.AreEqual(byte.MaxValue, buffer[read - 1]);
                    Assert.AreEqual(0, buffer[read]);
                    Array.Clear(buffer, 0, read);
                }
                readBytes += read;
            } while (read > 0);
            return readBytes;
        }

        [TestMethod]
        public void NormalCloseOnly()
        {

        }


    }
}
