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
}

extension Data {
    func hexEncodedString(separation: String = "") -> String {
        return reduce("") { $0 + String(format: "%02X\(separation)", $1) }
    }
}

extension X509CertificateTests {
    var certificateData: String {
        return "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"
    }

    func x509() throws -> X509Certificate {
        guard let certData = Data(base64Encoded: certificateData) else { fatalError("Failed to parse certificate") }
        return try X509Certificate(data: certData)
    }
}
