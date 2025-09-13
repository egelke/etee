/*
 *  This file is part of eH-I.
 *  Copyright (C) 2020 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;

/// <summary>
/// The certificate or other object is revoked.
/// </summary>
public class RevocationException<T> : Exception where T : Asn1Encodable
{
    /// <summary>
    /// The object with the revocation info
    /// </summary>
    /// <value>The CRL or OCSP object that contains the revocation</value>
    public T RevocationInfo { get; }

    /// <summary>
    /// Default contstructor
    /// </summary>
    /// <returns>New instance</returns>
    public RevocationException(T proof) : base() => RevocationInfo = proof;

    /// <summary>
    /// Contstructor with message
    /// </summary>
    /// <returns>New instance</returns>
    public RevocationException(T proof, String msg) : base(msg) => RevocationInfo = proof;

    /// <summary>
    /// Contstructor with message an cause.
    /// </summary>
    /// <returns>New instance</returns>
    public RevocationException(T proof, String msg, Exception cause) : base(msg, cause) => RevocationInfo = proof;
}