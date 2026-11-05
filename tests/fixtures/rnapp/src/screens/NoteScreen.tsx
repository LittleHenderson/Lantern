import React, { useEffect, useState } from 'react';
import { Text } from 'react-native';
import { findNote } from '../db/notes';

export default function NoteScreen({ route }) {
  const [note, setNote] = useState(null);
  useEffect(() => {
    findNote(route.params.id).then(setNote);
  }, [route.params.id]);
  return <Text>{note?.body}</Text>;
}
