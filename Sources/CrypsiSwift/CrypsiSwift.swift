import Foundation
import CCrypsi

public enum CrypsiError : Error {
    case digestError
}

public func scrypsi_md5(data: String) throws -> String {
    var md5DigestDst: UnsafeMutablePointer<UInt8>? = nil
    var md5DigestLengthDst: Int32 = 0

    do {
        try withUnsafeMutablePointer(to: &md5DigestDst) {
            let pointer: UnsafePointer<Int8>? = NSString(string: data).utf8String
            let length = NSString(string: data).length

            let res = crypsi_md5(pointer, length, $0, &md5DigestLengthDst)
            if res != 0 {
                throw CrypsiError.digestError
            }
        }
    } catch {
        throw CrypsiError.digestError
    }

    if let md5DigestDst = md5DigestDst {
        defer { md5DigestDst.deallocate() }

        return String(cString: md5DigestDst);
    }

    throw CrypsiError.digestError
}