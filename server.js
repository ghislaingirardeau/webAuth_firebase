import express from 'express';
import 'dotenv/config';
import session from 'express-session';
import cors from 'cors';
import bodyParser from 'body-parser';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

import admin from './firebase.js';

const app = express();
const port = process.env.PORT || 3000;

// Configuration WebAuthn
const rpID = 'localhost'; // Domaine de votre application
const origin = `http://${rpID}:9200`; // Changez pour https en production

// Configuration de base
app.use(
  cors({
    origin: 'http://localhost:9200', // URL de votre application Quasar
    credentials: true,
  })
);

app.use(bodyParser.json());

app.use(
  session({
    secret: 'votre-secret-tres-securise',
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60, //* le token ne sera valable qu'un heure
      sameSite: 'lax',
    },
  })
);

let userDBCredential = {};

/* REGISTRATION */

app.get('/auth/generate-registration-options', async (req, res) => {
  const user = {
    id: '123',
    name: 'gigi',
    displayName: 'Alice',
    uid: 'alice1744963593816',
  };

  const options = await generateRegistrationOptions({
    rpName: 'Mon App Quasar',
    rpID: rpID,
    userID: isoUint8Array.fromUTF8String(user.uid),
    userName: user.name,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // pour empreinte digitale
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred',
    },
  });

  req.session.challenge = options.challenge;
  req.session.user = user;

  console.log('options', options);

  res.json(options);
});

app.post('/auth/verify-registration', async (req, res) => {
  const { attResp } = req.body;
  const expectedChallenge = req.session.challenge;

  const verification = await verifyRegistrationResponse({
    response: attResp,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
  });

  // Génère un nouveau UID et enregistre le

  // TODO: doit vérifier si l'utilisateur existe déjà dans firestore, si n'existe pas créer un nouvelle uid
  // Ou oblige à la 1ere connection de se connecter via firebase/google => user aura alors forcément un uid
  // Une fois la 1ere connection réussi, on propose coté front à l'utilisateur de permettre la connexion via webAuth (évite le popup google)
  // ainsi on aura uid de user qui correspond à son uid de firebase auth
  const userUid = req.session.user.name + Date.now();
  req.session.user.uid = userUid;

  if (verification.verified) {
    /* Credential a enregistrer dans la base de données */
    userDBCredential = {
      ...verification.registrationInfo.credential,
      userHandle: req.session.user.uid,
    };
    // une fois à cette étape on peut considérer que l'utilisateur est enregistré et donc connecté

    /* POUR LIER A FIREBASE - Créer un token via firebase admin module */
    /* FIREBASE AUTH - consquence de auth().createCustomToken */
    /* SI userUid n'existe pas, cela va créer un nouvel utilisateur mais sans infos supplémentaire*/
    /* SI userUid existe deja, alors l'authentification va fonctionner sur l'utilisateur dont uid correspond */
    const firebaseToken = await admin.auth().createCustomToken(userUid);

    res.json({ success: true, token: firebaseToken });
  } else {
    res.status(400).json({ success: false });
  }
});

/* LOGIN */

app.get('/auth/generate-authentication-options', async (req, res) => {
  /* récupère les credentials depuis la base de donnée */
  const userCredential = userDBCredential;

  const options = await generateAuthenticationOptions({
    rpID: rpID,
    allowCredentials: [
      {
        id: userCredential.id,
        type: 'public-key',
        transports: ['internal'],
      },
    ],
    userVerification: 'required',
  });

  req.session.challenge = options.challenge;

  res.json(options);
});

app.post('/auth/verify-authentication', async (req, res) => {
  const expectedChallenge = req.session.challenge;

  /* récupère les credentials depuis la base de donnée */
  const userCredential = userDBCredential;

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: userCredential.id,
      publicKey: userCredential.publicKey,
      counter: userCredential.counter,
      userHandle: userCredential.userHandle,
    },
  });

  if (verification.verified) {
    /* POUR LIER A FIREBASE - Créer un token via firebase admin module */
    // userUid: on utilise celui déjà enregistrer lors de register => donc on aura besoin de le stocker en DB !
    // TODO: comment récupérer le UID ici ?????
    // à recuperer dans le credential (comme ici alice) ?? => voir les consoles coté front si je peux avoir cet info via asseResp ?
    // ainsi je pourrais recup email, faire un check de firebase auth user si email existe => si existe recup de uid

    // const firebaseUid = verification.authenticationInfo.firebaseUid;
    const firebaseUid = req.body.response.userHandle;

    const firebaseToken = await admin.auth().createCustomToken(firebaseUid);

    req.session.challenge = undefined;
    req.session.loggedIn = true;
    // créer une session ou retourner un token
    res.json({ success: true, token: firebaseToken });
  } else {
    res.status(401).json({ success: false });
  }
});

/* LOGOUT */

/* WebAuthn sert uniquement à authentifier un utilisateur en prouvant qu’il possède une clé privée via un appareil biométrique.
Mais la session ou le token d'authentification reste ce qui maintient l’état connecté, comme dans un login classique. */
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Erreur de déconnexion' });
    }
    res.clearCookie('connect.sid'); // ou autre nom de cookie
    res.json({ success: true });
  });
});

/* IS USER CONNECTED ? */

app.get('/me', (req, res) => {
  res.json({ user: req.session.user });
});

/* MIDDLEWARE FOR CONNECTED USER */

function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.status(401).json({ message: 'Non authentifié' });
}

/* Suppression d'un appareil */
/* Par contre, si un utilisateur veut supprimer un appareil enregistré, là oui, tu dois :
supprimer son credential de ta base ou lui proposer une UI pour "gérer ses appareils" comme Google le fait */

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
