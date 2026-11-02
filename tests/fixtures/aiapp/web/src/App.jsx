import { useState } from 'react';
import { sendChat, runAgent } from './api';

export default function App() {
  const [text, setText] = useState('');
  return (
    <div>
      <input value={text} onChange={e => setText(e.target.value)} />
      <button onClick={() => sendChat(text)}>Ask</button>
      <button onClick={() => runAgent(text)}>Run</button>
    </div>
  );
}
