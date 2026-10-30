import { useState } from "react"
import { runBackup } from "../api"

const adminKey = import.meta.env.VITE_ADMIN_SECRET

export function BackupButton({ name }: { name: string }) {
  const start = () => runBackup(name)
  return <button onClick={start}>Back up now</button>
}

export default function Admin() {
  const [name, setName] = useState("nightly")
  return (
    <div>
      <input value={name} onChange={(e) => setName(e.target.value)} />
      <BackupButton name={name} />
      <small>{adminKey ? "key loaded" : ""}</small>
    </div>
  )
}
