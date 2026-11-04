import React, { useEffect } from 'react';
import { Linking } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import HomeScreen from './src/screens/HomeScreen';
import NoteScreen from './src/screens/NoteScreen';
import SettingsScreen from './src/screens/SettingsScreen';
import NoteRow from './src/screens/NoteRow';
import { handleLink } from './src/links/handleLink';
import { useIsReady } from './src/links/ready';

const Stack = createNativeStackNavigator();

const linking = {
  prefixes: ['pocketnotes://'],
  config: {
    screens: {
      Note: 'note/:id',
    },
  },
};

function SettingsStack() {
  return <SettingsScreen />;
}

export default function App() {
  const ready = useIsReady();
  useEffect(() => {
    const sub = Linking.addEventListener('url', (event) => {
      handleLink(event.url);
    });
    return () => sub.remove();
  }, []);
  return (
    <NavigationContainer linking={linking}>
      <Stack.Navigator>
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="Note" component={NoteScreen} />
        <Stack.Screen name="More" component={SettingsStack} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
