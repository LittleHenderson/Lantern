export async function sendChat(message) {
  const r = await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ message }) });
  return r.json();
}

export async function runAgent(task) {
  const r = await fetch('/api/agent/run', { method: 'POST', body: JSON.stringify({ task }) });
  return r.json();
}
