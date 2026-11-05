import { useState } from "react";

export default function Search() {
  const [q, setQ] = useState("");
  const [notes, setNotes] = useState([]);
  async function run() {
    const res = await fetch(`/api/notes/search?q=${q}`);
    setNotes(await res.json());
  }
  async function remove(id) {
    await fetch(`/api/notes/${id}`, { method: "DELETE" });
  }
  return (
    <div>
      <input value={q} onChange={(e) => setQ(e.target.value)} />
      <button onClick={run}>Search</button>
      {notes.map((n) => <button key={n.id} onClick={() => remove(n.id)}>{n.title}</button>)}
    </div>
  );
}
