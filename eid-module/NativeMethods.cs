using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace Egelke.Fedict.Eid
{

    public class NativeMethods
    {
        [DllImport("winscard.dll")]
        internal static extern uint SCardEstablishContext([MarshalAs(UnmanagedType.U4)] ContextScope dwScope, IntPtr pvReserved1, IntPtr pvReserved2, out CardContextSafeHandler phContext);

        [DllImport("winscard.dll")]
        internal static extern uint SCardReleaseContext(IntPtr hContext);

        [DllImport("winscard.dll")]
        internal static extern uint SCardListReaders(CardContextSafeHandler hContext, IntPtr mszGroups, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex=3)] Char[] mszReaders, [In, Out] ref int pcchReaders);

        [DllImport("winscard.dll")]
        internal static extern uint SCardListCards(CardContextSafeHandler hContext, byte[] pbAtr, IntPtr rgguidInterfaces, int cguidInterfaceCount, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] Char[] mszCards, [In, Out] ref int pcchCards);

        [DllImport("winscard.dll")]
        internal static extern uint SCardGetStatusChange(CardContextSafeHandler hContext, int dwTimeout, [In, Out] SCARD_READERSTATE[] rgReaderStates, int cReaders);

        [DllImport("winscard.dll")]
        internal static extern uint SCardConnect(CardContextSafeHandler hContext, [MarshalAs(UnmanagedType.LPStr)] String szReader, CardShareMode dwShareMode, CardProtocols dwPreferredProtocols, out CardSafeHandler phCard, out CardProtocols pdwActiveProtocol);
        
        [DllImport("winscard.dll")]
        internal static extern uint SCardDisconnect(IntPtr hCard, CardDisposition dwDisposition);

        [DllImport("winscard.dll")]
        internal static extern uint SCardGetAttrib(CardSafeHandler hCard, CardAttrId dwAttrId, IntPtr pbAttr, ref int pcbAttrLen);

        [DllImport("winscard.dll")]
        internal static extern uint SCardBeginTransaction(CardSafeHandler hCard);

        [DllImport("winscard.dll")]
        internal static extern uint SCardEndTransaction(CardSafeHandler hCard, CardDisposition dwDisposition);

        [DllImport("winscard.dll")]
        internal static extern uint SCardTransmit(CardSafeHandler hCard, SCARD_IO_REQUEST pioSendPci, byte[] pbSendBuffer, int cbSendLength, [In, Out] SCARD_IO_REQUEST pioRecvPci, [Out] byte[] pbRecvBuffer, [In, Out] ref int pcbRecvLength);

        
    }
}
