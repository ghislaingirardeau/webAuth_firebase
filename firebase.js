import admin from 'firebase-admin';

import 'dotenv/config';

import { readFile } from 'fs/promises';
const serviceAccount = JSON.parse(
  await readFile(
    new URL(process.env.GOOGLE_APPLICATION_CREDENTIALS, import.meta.url)
  )
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

export { admin, db };
