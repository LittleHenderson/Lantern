import React from 'react';
import { Pressable, Text } from 'react-native';

export default function NoteRow({ note, onPress }) {
  return <Pressable onPress={onPress}><Text>{note.title}</Text></Pressable>;
}
