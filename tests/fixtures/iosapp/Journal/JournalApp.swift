import SwiftUI

@main
struct JournalApp: App {
    let store = EntryStore()

    var body: some Scene {
        WindowGroup {
            ContentView(store: store)
                .onOpenURL { url in
                    DeepLink.handle(url, store: store)
                }
        }
    }
}
