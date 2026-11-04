import XCTest
@testable import Journal

final class JournalTests: XCTestCase {
    func testAllIsEmpty() {
        XCTAssertEqual(EntryStore().all(), [])
    }
}
