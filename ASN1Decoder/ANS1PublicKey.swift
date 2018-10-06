//
//  ANS1PublicKey.swift
//  ASN1Decoder
//
//  Created by Victor Maraccini on 02/10/18.
//  Copyright © 2018 Filippo Maguolo. All rights reserved.
//

import Foundation

public class ANS1PublicKey {
    private let OID_ECPublicKey = "1.2.840.10045.2.1"
    private let OID_RSAEncryption = "1.2.840.113549.1.1.1"

    let pkBlock: ASN1Object

    init(pkBlock: ASN1Object) {
        self.pkBlock = pkBlock
    }

    public var algOid: String? {
        return pkBlock.sub(0)?.sub(0)?.value as? String
    }

    public var algName: String? {
        return ASN1Object.oidDecodeMap[algOid ?? ""]
    }

    public var algParams: String? {
        return pkBlock.sub(0)?.sub(1)?.value as? String
    }

    public var key: Data? {
        guard
            let algOid = algOid,
            let keyData = pkBlock.sub(1)?.value as? Data else {
                return nil
        }

        switch algOid {
        case OID_ECPublicKey:
            return keyData

        case OID_RSAEncryption:
            guard let publicKeyAsn1Objects = (try? ASN1DERDecoder.decode(data: keyData)) else {
                return nil
            }
            guard let publicKeyModulus = publicKeyAsn1Objects.first?.sub(0)?.value as? Data else {
                return nil
            }
            return publicKeyModulus

        default:
            return nil
        }
    }
}
