import { Linking } from 'react-native';
import { findNote } from '../db/notes';

export async function handleLink(url: string) {
  const { queryParams } = Linking.parse(url);
  const id = String(queryParams?.id ?? '');
  return findNote(id);
}
