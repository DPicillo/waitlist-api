const express = require('express');
const fetch = require('node-fetch');
const disposableEmails = require('disposable-email-domains');
require('dotenv').config();

const app = express();
app.use(express.json()); // Body-Parser für JSON

const USEPLUNK_URL = 'https://api.useplunk.com/v1/track';
const AUTH_HEADER = `Bearer ${process.env.USEPLUNK_KEY}`;

const isSuspiciousEmail = (email) => {
  // Überprüfe, ob die Domain der E-Mail in der Liste der verdächtigen Domains ist
  const domain = email.split('@')[1];
  if (disposableEmails.includes(domain)) {
    return true;
  }

  // Überprüfe auf zufällige E-Mails (z. B. eine lange Folge von zufälligen Zeichen)
  const randomPattern = /[a-z0-9]{10,}/i;
  if (randomPattern.test(email.split('@')[0])) {
    return true;
  }

  return false;
};

app.post('/api/track', async (req, res) => {
  const { email, event, subscribed } = req.body;

  if (!email || !event) {
    return res.status(400).json({ error: 'email und event sind erforderlich' });
  }

  // Überprüfe die E-Mail auf Verdacht
  if (isSuspiciousEmail(email)) {
    return res.status(400).json({ error: 'Verdächtige E-Mail-Adresse erkannt' });
  }

  try {
    const response = await fetch(USEPLUNK_URL, {
      method: 'POST',
      headers: {
        'Authorization': AUTH_HEADER,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, event, subscribed: !!subscribed })
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: data });
    }
    // Erfolg: gib das Useplunk-Response-Objekt zurück
    res.json(data);

  } catch (err) {
    console.error('Useplunk-Error:', err);
    res.status(500).json({ error: 'Interner Serverfehler' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server läuft auf http://localhost:${port}`);
});
