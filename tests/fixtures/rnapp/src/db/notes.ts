import * as SQLite from 'expo-sqlite';
import AsyncStorage from '@react-native-async-storage/async-storage';

const API = 'http://notes.example.com/api';

export async function openDb() {
  return SQLite.openDatabaseAsync('notes.db');
}

export async function findNote(id: string) {
  const db = await openDb();
  return db.getFirstAsync(`SELECT * FROM notes WHERE id = '${id}'`);
}

export async function allNotes() {
  const db = await openDb();
  return db.getAllAsync('SELECT * FROM notes ORDER BY id');
}

export async function saveLogin(token: string) {
  console.log('saving token', token);
  await AsyncStorage.setItem('auth_token', token);
  return fetch(API + '/login', { method: 'POST', body: token });
}
