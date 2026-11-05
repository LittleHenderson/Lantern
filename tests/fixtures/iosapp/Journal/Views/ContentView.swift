import SwiftUI

struct ContentView: View {
    let store: EntryStore
    @State private var entries: [String] = []

    var body: some View {
        NavigationStack {
            List(entries, id: \.self) { e in
                NavigationLink(e) { EntryView(id: e, store: store) }
            }
            .onAppear { reload() }
            .toolbar { Button("Sync", action: sync) }
        }
    }

    private func reload() {
        entries = store.all()
    }

    private func sync() {
        Sync.shared.push(entries)
    }
}
