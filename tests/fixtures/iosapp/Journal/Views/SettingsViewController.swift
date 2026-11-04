import UIKit

class SettingsViewController: UIViewController {
    private let auth = Auth()

    override func viewDidLoad() {
        super.viewDidLoad()
        print("signing in with password \(auth.password)")
    }

    @IBAction func signIn(_ sender: Any) {
        auth.save(token: "abc")
    }
}
