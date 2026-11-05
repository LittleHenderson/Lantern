import SwiftUI

struct EntryView: View {
    let id: String
    let store: EntryStore

    var body: some View {
        Text(store.entry(id: id) ?? "")
    }
}
