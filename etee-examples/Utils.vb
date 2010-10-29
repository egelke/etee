
' This file is part of .Net ETEE for eHealth.
'
' .Net ETEE for eHealth is free software: you can redistribute it and/or modify
' it under the terms of the GNU Lesser General Public License as published by
' the Free Software Foundation, either version 3 of the License, or
' (at your option) any later version.
' 
' .Net ETEE for eHealth  is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU Lesser General Public License for more details.

' You should have received a copy of the GNU Lesser General Public License
' along with Foobar.  If not, see <http://www.gnu.org/licenses/>.


Imports System.Security.Cryptography.X509Certificates
Imports Siemens.EHealth.Etee.Crypto.Decrypt
Imports System.Runtime.InteropServices

Public Class Utils
    Public Shared Function GetNewSecretKey(<Out()> ByRef keyId() As Byte) As Byte()
        keyId = Nothing
        Return Nothing
    End Function

    Public Shared ReadOnly Property SelfAuth() As X509Certificate2
        Get
            Return Nothing
        End Get
    End Property

    Public Shared ReadOnly Property SelfEnc() As X509Certificate2
        Get
            Return Nothing
        End Get
    End Property

    Public Shared Function ReadFully(ByVal file As [String]) As Byte()
        Return Nothing
    End Function

    Public Shared Sub Check(ByVal result As EtkSecurityInformation)


    End Sub

End Class
