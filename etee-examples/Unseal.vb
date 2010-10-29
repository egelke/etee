
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

Imports Siemens.EHealth.Etee.Crypto.Decrypt
Imports System.IO
Imports Siemens.EHealth.Etee.Crypto

Public Class Unseal
    Public Sub Unknown()
        'Create a IAnonymousDataSealer instance
        Dim unsealer As IAnonymousDataUnsealer = DataUnsealerFactory.Create()

        'Read the key id send by the sender
        Dim keyId As Byte() = Utils.ReadFully("protectedForGroup.kid")
        'Get the key from the KGSS
        Dim key As Byte() = GetKeyFromKGSS(keyId)
        'Create a secrte key object
        Dim skey As New SecretKey(keyId, key)

        Dim result As UnsealResult
        Dim file As New FileStream("protectedForGroup.msg", FileMode.Open)
        Using file
            result = unsealer.Unseal(file, skey)
        End Using
        'Check if the content is in order
        If result.SecurityInformation.ValidationStatus <> ValidationStatus.Valid Then
            Throw New Exception(result.SecurityInformation.ToString())
        End If
        'Check if sender and receiver used valid and up to spec certificates
        If result.SecurityInformation.TrustStatus <> TrustStatus.Full Then
            Throw New Exception(result.SecurityInformation.ToString())
        End If
        'Check if the sender is allowed to send a message (application specific)
        VerifySender(result.Sender)
        'Use the message (application specific)
        ImportMessage(result.UnsealedData)
    End Sub

    Private Function GetKeyFromKGSS(ByVal keyId As Byte()) As Byte()
        Throw New NotImplementedException()
    End Function

    Public Sub Known()
        'Create a IDataSealer instance
        Dim unsealer As IDataUnsealer = DataUnsealerFactory.Create(Utils.SelfEnc, Utils.SelfAuth)

        Dim result As UnsealResult
        Dim file As New FileStream("protectedForMe.msg", FileMode.Open)
        Using file
            result = unsealer.Unseal(file)
        End Using
        'Check if the content is in order
        If result.SecurityInformation.ValidationStatus <> ValidationStatus.Valid Then
            Throw New Exception(result.SecurityInformation.ToString())
        End If
        'Check if sender and receiver used valid and up to spec certificates
        If result.SecurityInformation.TrustStatus <> TrustStatus.Full Then
            Throw New Exception(result.SecurityInformation.ToString())
        End If
        'Check if the sender is allowed to send a message (application specific)
        VerifySender(result.Sender)
        'Use the message (application specific)
        ImportMessage(result.UnsealedData)
    End Sub

    Private Sub ImportMessage(ByVal stream As Stream)
        Throw New NotImplementedException()
    End Sub

    Private Sub VerifySender(ByVal x509Certificate2 As System.Security.Cryptography.X509Certificates.X509Certificate2)
        Throw New NotImplementedException()
    End Sub
End Class
