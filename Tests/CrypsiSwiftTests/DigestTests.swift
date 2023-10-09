import Foundation
import XCTest
@testable import CrypsiSwift

final class DigestTests: XCTestCase {
    func testMd5DigestShouldEqualToExpected() throws {
        let data: String = "wuriyanto"
        let expected: String = "60e1bc04fa194a343b50ce67f4afcff8"

        do {
            let actual = try scrypsi_md5(data: data)
            XCTAssertEqual(actual, expected)
        } catch {
            XCTAssertNoThrow(error)
        }
    }
}