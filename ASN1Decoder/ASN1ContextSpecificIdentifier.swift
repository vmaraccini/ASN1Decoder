import Foundation

public protocol ASN1ContextSpecificIdentifier: RawRepresentable where RawValue == UInt8 {}

public enum SubjectAlternativeNamesIdentifier: UInt8, ASN1ContextSpecificIdentifier {
    /* From https://tools.ietf.org/html/rfc5280#section-4.2.1.6
     -- subject alternative name extension OID and syntax

     id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

     SubjectAltName ::= GeneralNames

     GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

     GeneralName ::= CHOICE {
     otherName                 [0]  AnotherName,
     rfc822Name                [1]  IA5String,
     dNSName                   [2]  IA5String,
     x400Address               [3]  ORAddress,
     directoryName             [4]  Name,
     ediPartyName              [5]  EDIPartyName,
     uniformResourceIdentifier [6]  IA5String,
     iPAddress                 [7]  OCTET STRING,
     registeredID              [8]  OBJECT IDENTIFIER }
     */
    case otherName = 0
    case rfc822Name
    case dnsName
    case x400Address
    case directoryName
    case ediPartyName
    case uniformResourceIdentifier
    case ipAddress
    case registeredID
}
