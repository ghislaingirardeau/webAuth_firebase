import admin from 'firebase-admin';

import { readFile } from 'fs/promises';
const serviceAccount = JSON.parse(
  await readFile(new URL('./service_todo_list.json', import.meta.url))
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

export { admin, db };
