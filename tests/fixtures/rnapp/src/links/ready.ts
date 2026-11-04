import { useState } from 'react';

export function useIsReady() {
  const [ready] = useState(true);
  return ready;
}
