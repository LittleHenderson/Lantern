import Foundation

enum DeepLink {
    static func handle(_ url: URL, store: EntryStore) {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        guard let id = items?.first(where: { $0.name == "id" })?.value else { return }
        _ = store.entry(id: id)
    }
}
