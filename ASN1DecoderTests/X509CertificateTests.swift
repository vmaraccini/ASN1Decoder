//
//  X509CertificateTests.swift
//  ASN1DecoderTests
//
//  Created by Victor Maraccini on 02/10/18.
//  Copyright © 2018 Filippo Maguolo. All rights reserved.
//

import ASN1Decoder
import XCTest

class X509CertificateTests: XCTestCase {
    func testDecoding() {
        guard let certData = Data(base64Encoded: certificateData) else { return XCTFail("Failed to load PEM data") }
        XCTAssertNoThrow(try X509Certificate(data: certData))
    }

    func testParsingSerialNumber() throws {
        XCTAssertEqual(try x509().serialNumber?.hexEncodedString(), "0836BAA2556864172078584638D85C34")
    }

    func testParsingDistinguisedName() throws {
        XCTAssertEqual(try x509().subjectDistinguishedName,
                       "CN=www.digicert.com, SERIALNUMBER=5299537-0142, OU=SRE, O=\"DigiCert, Inc.\", L=Lehi, ST=Utah, C=US")
    }

    func testParsingIssuerDistinguishedName() throws {
        XCTAssertEqual(try x509().issuerDistinguishedName,
                       "CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US")
    }

    func testParsingAnternativeNames() throws {
        XCTAssertEqual(try x509().subjectAlternativeNames, ["www.digicert.com",
                                                            "digicert.com",
                                                            "content.digicert.com",
                                                            "www.origin.digicert.com",
                                                            "login.digicert.com",
                                                            "api.digicert.com",
                                                            "ws.digicert.com"])
    }

    func testParsingNotAfter() throws {
        XCTAssertEqual(try x509().notAfter, Date(timeIntervalSince1970: 1593518400))
    }

    func testParsingNotBefore() throws {
        XCTAssertEqual(try x509().notBefore, Date(timeIntervalSince1970: 1529971200))
    }

    func testCheckValidity() throws {
        XCTAssertFalse(try x509().checkValidity(Date(timeIntervalSince1970: 1529971199)))
        XCTAssertFalse(try x509().checkValidity(Date(timeIntervalSince1970: 1529971200)))
        XCTAssertFalse(try x509().checkValidity(Date(timeIntervalSince1970: 1593518400)))
        XCTAssertFalse(try x509().checkValidity(Date(timeIntervalSince1970: 1593518401)))

        XCTAssertTrue(try x509().checkValidity(Date(timeIntervalSince1970: 1529971201)))
        XCTAssertTrue(try x509().checkValidity(Date(timeIntervalSince1970: 1593518399)))
    }

    func testKeyUsage() throws {
        XCTAssertEqual(try x509().keyUsage, [true, false, true, false, false, false, false, false])
    }

    func testExtendedKeyUsage() throws {
        XCTAssertEqual(try x509().extendedKeyUsage, ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"])
    }

    func testIssuers() throws {
        let certificate = try x509()
        XCTAssertEqual(certificate.issuerOIDs, ["2.5.4.6", "2.5.4.10", "2.5.4.11", "2.5.4.3"])
        XCTAssertEqual(certificate.issuerOIDs.map { certificate.issuer(oid: $0) },
                       ["US",
                        "DigiCert Inc",
                        "www.digicert.com",
                        "DigiCert SHA2 Extended Validation Server CA"])
    }

    func testIssuerAlternativeNames() throws {
        //Couldn't find an example certificate with issuerAlternativeNames
        XCTAssertEqual(try x509().issuerAlternativeNames, [])
    }

    func testSignatureAlgorithm() throws {
        XCTAssertEqual(try x509().sigAlgName, "sha256WithRSAEncryption")
        XCTAssertEqual(try x509().sigAlgOID, "1.2.840.113549.1.1.11")
    }

    func testPublicKeyData() throws {
        XCTAssertEqual(try x509().publicKey?.key,
                       Data.from(hexString: "CE9F85CA393030B7F69869B49C105D503B2563D0E568D4D9A5CA2CD63595B23E0D298B9DE0814A04F7C09E354933FBAB1C118A96358EA5DEA281E7AA49248A8D426A3D36858EF24D86FE34C88C5146A8D59822ADB78B8F87A9A5E2D7F1FF6961606B3935AA4CB200E41003FA79E9B1BD9B93A4FC804CFC16672EA5492C624EC7D8A1806D5D23D0EBEAF6A9FBC41A3D16AEDEDF6C11DD9CC5EE08C7B80B75A606DEFC6C61FDC1C9C29348AB72ADB917D50CB476C4B1CBE182336113C44D6031AEEF468990FD9A19A3C21BE79905A7A9484FA50E3A491DCA225DA563D7219665B19479C247A0583B093FB5EFEE713458C918D7ED3988D62DAF3651861967070D80A0C18D23EB6C0572D029E65F585994DF46E19335FDF699AF2182777F57D018B6A8E389D01237649C8BE99B41CC82F6A06029D05679E1252B73C98CF7DB87E558B3D2A79ECE41E34CB6BE8EE56D07756CA151953E0F847AC0E6D840C6796E2623461B40423320F0455011F67311DAF45863B92511CB1F2A2DF2D12B5CCF43885E5C09BCDF7237AEA229364875BEBDBB8F6A03221D333DFB796BD2844EF995B070CEDF26F9F525F4763C32C0688DD052FECE2E1487DF651F42C93ED480AAD399B61F04B1880BE20D19790DEEBA30464376FBB4DEC5004131EF5A7C3432BEC981B8ED9F40DE50A2D8C2C45683EB29AA81532475866DBF5121BFB79717AFEE722A39"))
    }

    func testSignatureData() throws {
        XCTAssertEqual(try x509().signature,
                       Data.from(hexString: "8F7172DED4C8C626DC1F8A1B88D52E7719DA24140725F78A2EA16C5677B0127ECB9F532C6C16BA310E1370C5DF2640E1FB5777A16538A8B7A3FEC4C64EAD8C60271E425DB70BB74ED16474F4C3F3DFD39DA0ABB6CF19B1ECAE3B655EAD4C0E7F1CF03F859EFDAA4A01387FFF7043580C53820AA2368EE181FD158A1A700F29B975252B5A410AE08AD2327293202D0FDCF8A130FF64B0503A64C9E15C09E6B1CD09F748F1A911F4E618CB1F4609B79662FE4909C232CCFCAF65EE9C7880849D11A5894FC4CEBCB25A1AB8571FF345E060A17EB13967D6D59028B5AD1EB73A3DA525A339DAEB8F523BAB46C084BD5E52E5C4F054A6E8CF19A205BF65890E1C4DAE"))
    }

    func testVersion() throws {
        XCTAssertEqual(try x509().version, 3)
    }

    func testSerialNumber() throws {
        XCTAssertEqual(try x509().serialNumber, Data.from(hexString: "0836BAA2556864172078584638D85C34"))
    }

    func testSubjectOIDs() throws {
        let certificate = try x509()
        let oids = certificate.subjectOIDs
        XCTAssertEqual(oids.map { certificate.subject(oid: $0) },
                       ["Private Organization",
                        "US",
                        "Utah",
                        "5299537-0142",
                        "US",
                        "Utah",
                        "Lehi",
                        "DigiCert, Inc.",
                        "SRE",
                        "www.digicert.com"])
    }

    func testCriticalExtensionOIDs() throws {
        XCTAssertEqual(try x509().criticalExtensionOIDs, ["2.5.29.15", "2.5.29.19"])
    }

    func testNonCriticalExtensionOIDs() throws {
        XCTAssertEqual(try x509().nonCriticalExtensionOIDs, ["2.5.29.35", "2.5.29.14", "2.5.29.17", "2.5.29.37", "2.5.29.31", "2.5.29.32", "1.3.6.1.5.5.7.1.1", "1.3.6.1.4.1.11129.2.4.2"])
    }
}

extension Data {
    static func from(hexString hex: String) -> Data {
        func index(offset: Int) -> String.Index {
            return hex.index(hex.startIndex, offsetBy: offset)
        }

        let bytes = stride(from: 0, to: hex.count, by: 2)
            .map {index(offset: $0)...index(offset: $0 + 1) }
            .compactMap { UInt8(hex[$0], radix: 16) }

        return Data(bytes: bytes)
    }

    func hexEncodedString(separation: String = "") -> String {
        return reduce("") { $0 + String(format: "%02X\(separation)", $1) }
    }
}

extension X509CertificateTests {
    var certificateData: String {
        return "MIIItzCCB5+gAwIBAgIQCDa6olVoZBcgeFhGONhcNDANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVkIFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE4MDYyNjAwMDAwMFoXDTIwMDYzMDEyMDAwMFowgc8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRUwEwYLKwYBBAGCNzwCAQITBFV0YWgxFTATBgNVBAUTDDUyOTk1MzctMDE0MjELMAkGA1UEBhMCVVMxDTALBgNVBAgTBFV0YWgxDTALBgNVBAcTBExlaGkxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMQwwCgYDVQQLEwNTUkUxGTAXBgNVBAMTEHd3dy5kaWdpY2VydC5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDOn4XKOTAwt/aYabScEF1QOyVj0OVo1NmlyizWNZWyPg0pi53ggUoE98CeNUkz+6scEYqWNY6l3qKB56pJJIqNQmo9NoWO8k2G/jTIjFFGqNWYIq23i4+HqaXi1/H/aWFgazk1qkyyAOQQA/p56bG9m5Ok/IBM/BZnLqVJLGJOx9ihgG1dI9Dr6vap+8QaPRau3t9sEd2cxe4Ix7gLdaYG3vxsYf3BycKTSKtyrbkX1Qy0dsSxy+GCM2ETxE1gMa7vRomQ/ZoZo8Ib55kFp6lIT6UOOkkdyiJdpWPXIZZlsZR5wkegWDsJP7Xv7nE0WMkY1+05iNYtrzZRhhlnBw2AoMGNI+tsBXLQKeZfWFmU30bhkzX99pmvIYJ3f1fQGLao44nQEjdknIvpm0HMgvagYCnQVnnhJStzyYz324flWLPSp57OQeNMtr6O5W0HdWyhUZU+D4R6wObYQMZ5biYjRhtAQjMg8EVQEfZzEdr0WGO5JRHLHyot8tErXM9DiF5cCbzfcjeuoik2SHW+vbuPagMiHTM9+3lr0oRO+ZWwcM7fJvn1JfR2PDLAaI3QUv7OLhSH32UfQsk+1ICq05m2HwSxiAviDRl5De66MEZDdvu03sUAQTHvWnw0Mr7Jgbjtn0DeUKLYwsRWg+spqoFTJHWGbb9RIb+3lxev7nIqOQIDAQABo4ID5jCCA+IwHwYDVR0jBBgwFoAUPdNQpdagre7zSmAKZdMh1Pj41g8wHQYDVR0OBBYEFGywQ1b+PegS7NkS9WPVxMoHr7B2MIGRBgNVHREEgYkwgYaCEHd3dy5kaWdpY2VydC5jb22CDGRpZ2ljZXJ0LmNvbYIUY29udGVudC5kaWdpY2VydC5jb22CF3d3dy5vcmlnaW4uZGlnaWNlcnQuY29tghJsb2dpbi5kaWdpY2VydC5jb22CEGFwaS5kaWdpY2VydC5jb22CD3dzLmRpZ2ljZXJ0LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1nMi5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1nMi5jcmwwSwYDVR0gBEQwQjA3BglghkgBhv1sAgEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVngQwBATCBiAYIKwYBBQUHAQEEfDB6MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUgYIKwYBBQUHMAKGRmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJFeHRlbmRlZFZhbGlkYXRpb25TZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAX4GCisGAQQB1nkCBAIEggFuBIIBagFoAHYAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFkPjJMpQAABAMARzBFAiEAtvfxjDWBvpmqcq7+1X8lOyqKUJ8y5r31V4kV4tzQSPcCIG8AAjqwQwLG6ObfgMe0B06AwM7K1JEAsyv8QP5r/EPUAHYAVhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0AAAFkPjJMFgAABAMARzBFAiEAkDHYU+MhibIUpVtiPAFyEzv35P3Vwn5ODseJmDI6dZkCICb4xzUGBy7aEQKJLOuM1F0AvMjEEB1OQQc9IWEY7UdPAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8AAAFkPjJNlAAABAMARzBFAiBSMM3aExfTbMG1btIu+LCW9ALj4FT6scxUUgy5+OSH/gIhAPtqsgHiH6m6Qml1E9smajxYa773+YZdxMKbtEEe2ZV8MA0GCSqGSIb3DQEBCwUAA4IBAQCPcXLe1MjGJtwfihuI1S53GdokFAcl94ouoWxWd7ASfsufUyxsFroxDhNwxd8mQOH7V3ehZTiot6P+xMZOrYxgJx5CXbcLt07RZHT0w/Pf052gq7bPGbHsrjtlXq1MDn8c8D+Fnv2qSgE4f/9wQ1gMU4IKojaO4YH9FYoacA8puXUlK1pBCuCK0jJykyAtD9z4oTD/ZLBQOmTJ4VwJ5rHNCfdI8akR9OYYyx9GCbeWYv5JCcIyzPyvZe6ceICEnRGliU/EzryyWhq4Vx/zReBgoX6xOWfW1ZAota0etzo9pSWjOdrrj1I7q0bAhL1eUuXE8FSm6M8ZogW/ZYkOHE2u"
    }

    func x509() throws -> X509Certificate {
        guard let certData = Data(base64Encoded: certificateData) else { fatalError("Failed to parse certificate") }
        return try X509Certificate(data: certData)
    }
}
