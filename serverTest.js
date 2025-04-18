// server.js
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const {
  isoBase64URL,
  isoUint8Array,
} = require('@simplewebauthn/server/helpers');

const app = express();
const port = process.env.PORT || 3000;

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

// Configuration WebAuthn
const rpID = 'localhost'; // Domaine de votre application
const rpName = 'Mon Application Quasar PWA';
const origin = `http://${rpID}:9200`; // Changez pour https en production

// Stocker les informations des utilisateurs et de leurs authentificateurs
// En production, utilisez une base de données
const users = new Map();
const authenticators = new Map();

// Générer des identifiants utilisateur uniques
const generateUserID = () => {
  return isoUint8Array.fromUTF8String(
    Date.now().toString(36) + Math.random().toString(36).substring(2)
  );
};

// Middleware pour vérifier si l'utilisateur existe
const userExists = (req, res, next) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: "Nom d'utilisateur requis" });
  }

  req.session.username = username;

  // Créer un utilisateur s'il n'existe pas
  if (!users.has(username)) {
    const userID = generateUserID();
    users.set(username, { id: userID, username, authenticators: [] });
    authenticators.set(userID, []);
  }

  next();
};

app.get('/', (req, res) => {
  res.send('Bienvenue sur le serveur WebAuthn !');
});

// Endpoints WebAuthn

//  Registration 1. Générer les options d'enregistrement
app.post(
  '/api/webauthn/generate-registration-options',
  userExists,
  async (req, res) => {
    const { username } = req.session;
    const user = users.get(username);

    // Obtenir les authenticateurs existants pour l'utilisateur
    const userAuthenticators = authenticators.get(user.id) || [];

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.id,
      userName: username,
      timeout: 60000, // 1 minute
      attestationType: 'none',
      excludeCredentials: userAuthenticators.map((authenticator) => ({
        id: authenticator.credentialID,
        type: 'public-key',
        transports: authenticator.transports || ['internal'],
      })),
      authenticatorSelection: {
        userVerification: 'required',
        // Préférer les authentificateurs intégrés à l'appareil (comme TouchID)
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        requireResidentKey: true,
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    });

    // Sauvegarder le challenge pour la vérification ultérieure
    req.session.currentChallenge = options.challenge;

    res.json(options);
  }
);

//  Registration 2. Vérifier la réponse d'enregistrement
app.post('/api/webauthn/verify-registration', async (req, res) => {
  const { username, currentChallenge } = req.session;
  const user = users.get(username);

  if (!user) {
    return res.status(400).json({ error: 'Utilisateur non trouvé' });
  }

  const expectedChallenge = currentChallenge;

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body.attResp,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { publicKey, id, counter, transports } =
        registrationInfo.credential;

      const newAuthenticator = {
        id,
        publicKey,
        counter: typeof counter === 'number' ? counter : 0,
        transports,
      };

      console.log('158', newAuthenticator);

      // Ajouter le nouvel authenticateur
      const userAuthenticators = authenticators.get(user.id) || [];
      authenticators.set(user.id, [...userAuthenticators, newAuthenticator]);

      // Mettre à jour les authenticateurs de l'utilisateur
      user.authenticators.push({
        id: isoBase64URL.fromBuffer(id),
      });

      req.session.currentChallenge = undefined;

      res.json({ verified });
    } else {
      res.status(400).json({ error: 'Échec de la vérification' });
    }
  } catch (error) {
    console.error('Erreur lors de la vérification:', error);
    res.status(400).json({ error: error.message });
  }
});

// 3. Générer les options d'authentification
app.post(
  '/api/webauthn/generate-authentication-options',
  userExists,
  async (req, res) => {
    const { username } = req.session;
    const user = users.get(username);

    // Obtenir les authenticateurs de l'utilisateur
    const userAuthenticators = authenticators.get(user.id) || [];

    console.log('194', userAuthenticators);

    if (userAuthenticators.length === 0) {
      return res.status(400).json({
        error: 'Aucun authentificateur enregistré pour cet utilisateur',
      });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      timeout: 60000,
      allowCredentials: userAuthenticators.map((authenticator) => ({
        id: authenticator.id,
        type: 'public-key',
        transports: authenticator.transports || ['internal'],
      })),
      userVerification: 'preferred',
    });

    // Sauvegarder le challenge pour la vérification ultérieure
    req.session.currentChallenge = options.challenge;

    res.json(options);
  }
);

// 4. Vérifier la réponse d'authentification
app.post('/api/webauthn/verify-authentication', async (req, res) => {
  const { username, currentChallenge } = req.session;

  const user = users.get(username);

  if (!user) {
    return res.status(400).json({ error: 'Utilisateur non trouvé' });
  }

  const expectedChallenge = currentChallenge;

  try {
    // Trouver l'authenticateur correspondant
    const userAuthenticators = authenticators.get(user.id) || [];

    const authenticator = userAuthenticators.find(
      (authr) => authr.id == req.body.attResp.rawId // compare en Buffer
    );

    if (!authenticator) {
      return res.status(400).json({ error: 'Authenticateur non trouvé' });
    }

    /* Erreur sur le counter,  même en mettant une valeur pas défaut, j'ai un retour undefined
    Ce qui fait planter la fonction de verifyAuthenticationResponse()
    */

    const verification = await verifyAuthenticationResponse({
      response: req.body.attResp,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        credentialID: authenticator.id,
        credentialPublicKey: Buffer.from(authenticator.publicKey),
        counter: 1,
      },
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verification;

    console.log('263', authenticationInfo);

    if (verified && authenticationInfo) {
      // Mettre à jour le compteur de l'authenticateur
      authenticator.counter = authenticationInfo.newCounter;

      req.session.currentChallenge = undefined;
      req.session.loggedIn = true;
      req.session.userID = user.id;

      res.json({ verified, username });
    } else {
      res.status(400).json({ error: 'Échec de la vérification' });
    }
  } catch (error) {
    console.error('Erreur lors de la vérification:', error);
    res.status(400).json({ error: error.message });
  }
});

// Vérifier le statut de connexion
app.get('/api/user/status', (req, res) => {
  if (req.session.loggedIn && req.session.userID) {
    const userID = req.session.userID;
    // Trouver l'utilisateur par ID
    let username = null;
    for (const [name, userData] of users.entries()) {
      if (userData.id === userID) {
        username = name;
        break;
      }
    }

    res.json({ loggedIn: true, username });
  } else {
    res.json({ loggedIn: false });
  }
});

// Route de déconnexion
app.post('/api/user/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Échec de la déconnexion' });
    }
    res.json({ success: true });
  });
});

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});

module.exports = app;
