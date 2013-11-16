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
using System.Text;
using System.IO;

namespace Egelke.eHealth.ETEE.Crypto.Test
{
    public class Utils
    {

        public static byte[] ReadFully(string file)
        {
            byte[] buffer = new byte[1024];
            FileStream s = new FileStream(file, FileMode.Open, FileAccess.Read);
            using (s)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    while (true)
                    {
                        int read = s.Read(buffer, 0, buffer.Length);
                        if (read <= 0)
                            return ms.ToArray();
                        ms.Write(buffer, 0, read);
                    }
                }
            }
        }

        private void WriteFully(string file, byte[] data)
        {
            FileStream s = new FileStream(file, FileMode.Create, FileAccess.Write);
            using (s)
            {
                s.Write(data, 0, data.Length);
            }
        }

        public static void Copy(Stream source, Stream destination)
        {
            int count = 0;
            byte[] buffer = new byte[1024];
            while ((count = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                destination.Write(buffer, 0, count);
            }
        }

    }
}
