import React, { useEffect, useState } from 'react';
import { FlatList } from 'react-native';
import { allNotes } from '../db/notes';
import NoteRow from './NoteRow';

export default function HomeScreen({ navigation }) {
  const [notes, setNotes] = useState([]);
  useEffect(() => {
    allNotes().then(setNotes);
  }, []);
  return <FlatList data={notes} renderItem={({ item }) => <NoteRow note={item} onPress={() => navigation.navigate('Note', { id: item.id })} />} />;
}
