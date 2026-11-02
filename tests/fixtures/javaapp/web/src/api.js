export async function getNote(id) {
  const r = await fetch(`/api/notes/${id}`);
  return r.json();
}

export async function deleteNote(id) {
  await fetch(`/api/notes/${id}`, { method: 'DELETE' });
}
