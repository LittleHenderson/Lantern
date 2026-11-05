import { useState } from 'react';

export default function Search() {
  const [q, setQ] = useState('');
  const [notes, setNotes] = useState([]);

  async function search() {
    const res = await fetch(`/api/notes?q=${encodeURIComponent(q)}`);
    setNotes(await res.json());
  }

  async function remove(id) {
    await fetch(`/api/notes/${id}`, { method: 'DELETE' });
    search();
  }

  return (
    <div>
      <input value={q} onChange={(e) => setQ(e.target.value)} />
      <button onClick={search}>Search</button>
      {notes.map((n) => (
        <p key={n.id}>{n.title} <button onClick={() => remove(n.id)}>Delete</button></p>
      ))}
    </div>
  );
}
