import Foundation
import CCrypsi

private func digest(hf:crypsi_digest_alg, data: String) throws -> String {
    var digestDst: UnsafeMutablePointer<UInt8>? = nil
    var digestLengthDst: Int32 = 0

    do {
        try withUnsafeMutablePointer(to: &digestDst) {
            let pointer: UnsafePointer<Int8>? = NSString(string: data).utf8String
            let length = NSString(string: data).length

            var res: Int32 = 0
            switch hf {
                case CRYPSI_MD5:
                    res = crypsi_md5(pointer, length, $0, &digestLengthDst)
                case CRYPSI_SHA1:
                    res = crypsi_sha1(pointer, length, $0, &digestLengthDst)
                case CRYPSI_SHA256:
                    res = crypsi_sha256(pointer, length, $0, &digestLengthDst)
                case CRYPSI_SHA384:
                    res = crypsi_sha384(pointer, length, $0, &digestLengthDst)
                case CRYPSI_SHA512:
                    res = crypsi_sha512(pointer, length, $0, &digestLengthDst)
                default: 
                    throw CrypsiError.digestError
            }

            if res != 0 {
                throw CrypsiError.digestError
            }
        }
    } catch {
        throw CrypsiError.digestError
    }

    if let digestDst = digestDst {
        defer { free(digestDst) }

        return String(cString: digestDst);
    } 

    throw CrypsiError.digestError
}

public func scrypsi_md5(data: String) throws -> String {
    return try digest(hf: CRYPSI_MD5, data: data)
}

public func scrypsi_sha1(data: String) throws -> String {
    return try digest(hf: CRYPSI_SHA1, data: data)
}

public func scrypsi_sha256(data: String) throws -> String {
    return try digest(hf: CRYPSI_SHA256, data: data)
}

public func scrypsi_384(data: String) throws -> String {
    return try digest(hf: CRYPSI_SHA384, data: data)
}

public func scrypsi_512(data: String) throws -> String {
    return try digest(hf: CRYPSI_SHA512, data: data)
}