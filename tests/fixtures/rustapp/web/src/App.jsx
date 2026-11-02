import { useState } from 'react';
import { getNote, deleteNote } from './api';

export default function App() {
  const [note, setNote] = useState(null);
  return (
    <div>
      <button onClick={() => getNote('1').then(setNote)}>Load</button>
      <button onClick={() => deleteNote('1')}>Delete</button>
      {note && <p>{note.Text}</p>}
    </div>
  );
}
