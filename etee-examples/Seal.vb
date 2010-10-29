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

Imports Siemens.EHealth.Etee.Crypto.Encrypt
Imports Siemens.EHealth.Etee.Crypto
Imports System.Collections.ObjectModel
Imports System.Text
Imports System.IO

Public Class Seal
    Public Sub MixedBytes()
        Dim msg As String = "My message"

        'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)

        'Create a secret key, keyId and Key are retreived from KGSS
        Dim keyId() As Byte
        Dim key() As Byte = Utils.GetNewSecretKey(keyId)
        Dim skey As New SecretKey(keyId, key)

        'Read the etk of a specific reciever
        Dim receiver As New EncryptionToken(Utils.ReadFully("other.etk"))
        'verify if it is (still) correct
        Utils.Check(receiver.Verify())

        'Create a list for the recievers, only one in this case
        Dim receivers As New List(Of EncryptionToken)
        receivers.Add(receiver)

        'Seal a string message, encoded as UTF8.
        Dim output() As Byte = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), Encoding.UTF8.GetBytes(msg), skey)

    End Sub

    Public Sub KnownStream()
        'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)

        'Read the etk of a specific reciever
        Dim receiver As New EncryptionToken(Utils.ReadFully("other.etk"))
        'verify if it is (still) correct
        Utils.Check(receiver.Verify())

        'Create a list for the recievers, only one in this case
        Dim receivers As New List(Of EncryptionToken)
        receivers.Add(receiver)

        'Seal as stream
        Dim output As Stream
        Dim file As New FileStream("text.txt", FileMode.Open)
        Using file
            output = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), file)
        End Using
    End Sub

    Public Sub MixedStream()


        'Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
        Dim sealer As IDataSealer = DataSealerFactory.Create(Utils.SelfAuth)

        'Create a secret key, keyId and Key are retreived from KGSS
        Dim keyId() As Byte
        Dim key() As Byte = Utils.GetNewSecretKey(keyId)
        Dim skey As New SecretKey(keyId, key)

        'Read the etk of a specific reciever
        Dim receiver As New EncryptionToken(Utils.ReadFully("other.etk"))
        'verify if it is (still) correct
        Utils.Check(receiver.Verify())

        'Create a list for the recievers, only one in this case
        Dim receivers As New List(Of EncryptionToken)
        receivers.Add(receiver)

        'Seal as stream
        Dim output As Stream
        Dim file As New FileStream("text.txt", FileMode.Open)
        Using file
            output = sealer.Seal(New ReadOnlyCollection(Of EncryptionToken)(receivers), file, skey)
        End Using
    End Sub
End Class
