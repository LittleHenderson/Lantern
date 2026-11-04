import React from 'react';
import { Button } from 'react-native';
import { saveLogin } from '../db/notes';

export default function SettingsScreen() {
  return <Button title="Sign in" onPress={() => saveLogin('demo')} />;
}
