import Foundation

protocol Uploader {
    func push(_ items: [String])
}

final class Auth {
    var password = ""

    func save(token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
    }
}

final class Sync: NSObject, Uploader, URLSessionDelegate {
    static let shared = Sync()

    func push(_ items: [String]) {
        let url = URL(string: "http://api.example.com/sync")!
        URLSession.shared.dataTask(with: url).resume()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}

extension String {
    func trimmed() -> String { trimmingCharacters(in: .whitespaces) }
}
