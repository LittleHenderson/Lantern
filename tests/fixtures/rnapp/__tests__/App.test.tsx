import { allNotes } from '../src/db/notes';

test('loads notes', async () => {
  expect(allNotes).toBeDefined();
});
