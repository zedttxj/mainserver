const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
// const csrf = require('csurf');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;
// const JWT_SECRET = 'supersecuresecret'; // 🔒 Replace with env var in prod
// const privateKey = fs.readFileSync(path.join(__dirname, './private.key'), 'utf-8');
// const publicKey = fs.readFileSync(path.join(__dirname, './room-public.pem'), 'utf-8');

const { runAuthenticatedClient, runAuthenticatedClient2Ways, requestCertificateFromHub } = require('./clientCertRequester');
let privateKey, publicKey, rating_privateKey;

(async () => {
  {
    const issued = await requestCertificateFromHub();
    const certificate = issued.certificate;
    privateKey = issued.privateKey;
    const caPublicKey = issued.caPublicKey;
    const roomId = issued.roomId;
    const result = await runAuthenticatedClient2Ways("wss://relay-h2hg.onrender.com/hub", certificate, privateKey, caPublicKey, roomId);
    publicKey = result.clientPubKey;
  }
  
  const issued = await requestCertificateFromHub();
  const certificate = issued.certificate;
  rating_privateKey = issued.privateKey;
  const caPublicKey = issued.caPublicKey;
  const roomId = issued.roomId;
  await runAuthenticatedClient("wss://relay-h2hg.onrender.com/hub", certificate, rating_privateKey, caPublicKey, roomId);
})();

// const rating_privateKey = fs.readFileSync(path.join(__dirname, './inter-service-private.key'), 'utf-8');

// const nov_privateKey = fs.readFileSync(path.join(__dirname, './nov-private.pem'), 'utf-8');
// const sign_publicKey = fs.readFileSync(path.join(__dirname, './rating-public.pem'), 'utf-8');
// const sign_privateKey = fs.readFileSync(path.join(__dirname, './rating-private.key'), 'utf-8');

const crypto = require("crypto");
const { publicKey: sign_publicKey, privateKey: sign_privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });


// 💡 Allow CORS from localhost for local frontend testing
// {test 3}
// const allowedOrigins = ["https://mainserver-eivi.onrender.com", "https://relay-h2hg.onrender.com", "https://ratings-iomx.onrender.com", "https://togetherjsserver.onrender.com", "https://zedttxj.github.io"];

// const corsOptions = {
//   origin: function (origin, callback) {
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   },
//   credentials: true,
// };

// app.use(cors(corsOptions)); // ✅ MUST come before routes
app.use(cors({
  origin: "https://zedttxj.github.io", // ✅ fixed allowed origin
  credentials: true                    // ✅ allow cookies
}));
app.use(helmet());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// const csrfProtection = csrf({ cookie: true });

function decodeJWT(token) {
  try {
    return jwt.decode(token); // No signature verification — just decoding
  } catch (err) {
    return null;
  }
}
app.get("/whoami", (req, res) => {
  const token = req.cookies.jwt;
  const decoded = decodeJWT(token);

  if (!decoded) return res.status(401).send("Invalid token");

  // 🧠 This is just for info — not trusted
  res.json({
    clientId: decoded.user_id,
    room_id: decoded.room_id,
    role: decoded.role
  });
});



const roomCreators = new Map(); // room_id → clientId
const roomBacklog = new Map(); // room_id → clientId
const creatorRooms = new Map(); // clientId → room_id
const creatorLocations = new Map(); // clientId → location

function verifyRating(token) {
  try {
    return jwt.verify(token, sign_publicKey, { algorithms: ['RS256'] });
  } catch (err) {
    return null; // or handle error
  }
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  } catch (err) {
    return null; // or handle error
  }
}

const inactive = new Map(); // clientId -> room abandoned/inactive

app.post('/api/rating', (req, res) => {

    // {test 2}
  const token = req.body.token;
  const parsed = verifyJWT(token);
  if (!parsed || !parsed.clientId || !parsed.roomId || !(typeof parsed.emoji === 'string' || typeof parsed.accept === "boolean")) {
    return res.status(400).json({ success: false, error: "Invalid token" });
  }

  const targetClientId = roomBacklog.get(parsed.roomId) || roomCreators.get(parsed.roomId);
  if (!targetClientId) return res.status(400).json({ success: false, error: "Room doesn't exist" });
  if (targetClientId === parsed.clientId) {
    if (parsed.accept) inactive.set(targetClientId, "inactive"); else inactive.set(targetClientId, "abandoned");
    return res.status(429).json({ success: false, message: "Can't rate yourself" });
  }

  const rating = jwt.sign(
    {
      clientId: String(parsed.clientId),
      targetClientId,
      emoji: parsed.emoji,
      roomId: String(parsed.roomId)
    },
    rating_privateKey,
    { algorithm: "RS256", expiresIn: "1m" }
  );

  const postData = JSON.stringify({ token: rating });

  const forwardReq = https.request({
        hostname: 'ratings-iomx.onrender.com',
        path: '/api/rating',
        method: 'POST',
        headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
        }
    }, (forwardRes) => {
        let body = '';
        forwardRes.on('data', (chunk) => {
        body += chunk;
        });

    forwardRes.on('end', () => {
        try {
            const result = JSON.parse(body);
            // console.log("✅ Received from rating.js:", result);

            if (result.success) {
            return res.status(200).json({ success: true, text: "Someone left a rating", clientId: targetClientId});
            } else {
            return res.status(400).json({ success: false, error: result.error || "Unknown error" });
            }
        } catch (err) {
            console.error("❌ Failed to parse response from rating.js:", err);
            return res.status(502).json({ success: false, error: "Invalid response from rating service" });
        }
        });
    });

    forwardReq.on('error', (e) => {
        console.error(`❌ Problem sending rating to backend: ${e.message}`);
        res.status(500).json({ success: false, error: "Rating service unreachable" });
    });

    forwardReq.write(postData);
    forwardReq.end();
});

app.post('/api/room-closed', (req, res) => {
  // {test 2}
  const token = req.body.token;
  const roomId = String(verifyJWT(token)?.roomId).trim().normalize();

  if (!roomId) {
      console.log(`❌ JWT mismatch for roomId ${roomId}`);
      return res.status(400).json({ success: false, error: "JWT mismatch for roomId" });
  }

  const clientId = roomCreators.get(roomId);

  creatorLocations.delete(clientId); // 💡 delete reverse map first
  if (creatorRooms.get(clientId) === roomId) creatorRooms.delete(clientId); // In case the provider left earlier, we don't wanna delete the new room that provider is holding. This is for tracking the previous room they hold.
  if (roomBacklog.has(roomId)) roomBacklog.delete(roomId); // If this is room is in backlog, delete it when it's closed
  if (inactive.has(clientId)) inactive.delete(clientId); // room doesn't exist anymore, why should the room-consent message be active?
  roomCreators.delete(roomId); // Officially closed the room

  console.log(`✅ Room ${roomId} by ${clientId} closed`);
  res.json({ ok: true });
});

app.post('/api/room-opened', (req, res) => {
  // {test 2}
  const token = req.body.token;
  const roomId = String(verifyJWT(token)?.roomId).trim().normalize();

  if (!roomId) {
      console.log(`❌ JWT mismatch for roomId ${roomId}`);
      return res.status(400).json({ success: false, error: "JWT mismatch for roomId" });
  }
  
  console.log('Verified room opened:', roomId); // provider can't occupy the room that they're not in
  roomCreators.set(roomId, null);
  res.json({ ok: true });
});

app.post('/api/geo-update', (req, res) => {
  // {test 2}
  const token = req.cookies.jwt_long;
  const clientId = verifyRating(token)?.clientId;
  const {data, broadcast, name} = req.body
  if (clientId && roomCreators.get(creatorRooms.get(clientId)) === clientId) {
    const current = creatorLocations.get(clientId) || {};
    creatorLocations.set(clientId, {
      ...current,
      ...(broadcast ? { ...data, name } : {}),
      broadcast
    });
  }
  res.json({ ok: true });
});

// inactive: the provider left the room but currently not joining other rooms
  // should be hidden?. Maybe promote to warning if they set broadcast = false? What if they come back? Backlog should not be created if they come back before joining different room
// suspicious: the provider left the room but currently in other room
  // should be visible. Should it still stay in suspicious if they set broadcast = false? What action should we take?
// warning: the provider is currently in the room but left some room hanging
  // provider's choice. Should it still stay in warning if they set broadcast = false? What action should we take?
// ok: the provider is currently in the room and left no rooms hanging
  // provider's choice
app.post('/api/map-update', (req, res) => {

  // {test 2}
  const seen = new Map(); // clientId → count
  const liveLocations = [];

  for (const [roomId, clientId] of roomBacklog.entries()) {
    if (!seen.has(clientId)) seen.set(clientId, 0);
    seen.set(clientId, seen.get(clientId) + 1);
    const loc = creatorLocations.get(clientId);
    if (loc) {
      const count = seen.get(clientId);
      const status = `suspicious${count}`;
      liveLocations.push({ name: loc.name, roomId, ...loc, status});
    }
  }

  // {test 3}
  const creatorIds = [...roomCreators.values()];
  let ratingMap = new Map();
  const postData = JSON.stringify({ clientIds: creatorIds });

  const forwardReq = https.request({
    hostname: 'ratings-iomx.onrender.com',
    path: '/api/summary',
    method: 'POST',
    headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData)
    }
  }, (forwardRes) => {
    let body = '';
    forwardRes.on('data', (chunk) => {
    body += chunk;
    });

    forwardRes.on('end', () => {
      try {
        const result = JSON.parse(body);

        for (const [clientId, stats] of Object.entries(result)) {
          ratingMap.set(clientId, stats);
        }
        
        for (const [roomId, clientId] of roomCreators.entries()) {
          const loc = creatorLocations.get(clientId);
          if (loc && loc.broadcast) {
            const count = seen.get(clientId) || 0;
            let status;
            if (count > 0) {
              status = `warning${count}`;
            } else if (inactive.has(clientId)) {
              status = inactive.get(clientId); // "inactive" or "abandoned"
            } else {
              status = "ok";
            }
            const stats = ratingMap.get(clientId) || { given: 0, received: 0, avg: 0 }; // {test 3}
            liveLocations.push({ name: loc.name, roomId, ...loc, status, ratingsGiven: stats.given, ratingsReceived: stats.received, averageEmojiScore: stats.avg});
          }
        }
        liveLocations.sort((a, b) => b.active - a.active);
        res.setHeader("Content-Type", "application/json");
        res.json(liveLocations);

      } catch (err) {
          console.error("❌ Failed to parse response from rating.js:", err);
          return res.status(502).json({ success: false, error: "Invalid response from rating service" });
      }
    });
  });

  forwardReq.on('error', (e) => {
      console.error(`❌ Problem sending rating to backend: ${e.message}`);
      res.status(500).json({ success: false, error: "Rating service unreachable" });
  });

  forwardReq.write(postData);
  forwardReq.end();

});

// function checkroom(mytoken) {
//   const postData = JSON.stringify({ token: mytoken });
//   const forwardreq = https.request({
//     hostname: 'localhost',
//     port: 8080,
//     path: '/api/room-check',
//     method: 'POST',
//     headers: {
//       'Content-Type': 'application/json',
//       'Content-Length': postData.length
//     }
//   }, (res) => {
//     let data = '';

//     // 🔄 Accumulate data chunks
//     res.on('data', (chunk) => {
//       data += chunk;
//     });

//     // ✅ Done receiving: parse the result
//     res.on('end', () => {
//       try {
//         const result = JSON.parse(data);
//         // console.log("✅ Hub server says:", result);

//         return result.ok;
//       } catch (err) {
//         console.error("❌ Failed to parse hub server response:", err);
//       }
//     });
//   });

//   forwardreq.on('error', (e) => {
//     console.error(`Problem with request: ${e.message}`);
//   });

//   forwardreq.write(postData);
//   forwardreq.end();
// }

app.post("/register-guest", (req, res) => {
  const myjwt = req.cookies.jwt_long;

  if (!myjwt) return res.status(401).send("Missing token");
  const parsed = verifyRating(myjwt);
  if (!parsed) return res.status(411).send("Incorrect or expired token");
  const clientId = parsed.clientId;
  if (!clientId) return res.status(421).send("No clientId, how?");
  const { room_id } = req.body;
  
  if (!room_id) {
    return res.status(400).send("Missing room_id");
  }

  const previousRoom = creatorRooms.get(clientId);
  if (previousRoom && previousRoom !== room_id && roomCreators.get(previousRoom) === clientId) {
    // If client previously owned a different room, remove it and pushed to backlog
    roomCreators.delete(previousRoom); // pushing to backlog to track the rating
    roomBacklog.set(previousRoom, clientId); // backlog shouldn't be deleted unless it's closed
    // return res.json({ok: false});
  }
  // Determine if this is the first registrant
  const isCreator = roomCreators.has(room_id) && roomCreators.get(room_id) === null || roomCreators.get(room_id) === clientId;
  if (isCreator) {
    // Update mappings
    roomCreators.set(room_id, clientId);
    creatorRooms.set(clientId, room_id);
  }

  const role = isCreator ? "provider_guest" : "guest";

  const token = jwt.sign(
    {
      user_id: clientId,
      role
    },
    privateKey,
    { algorithm: "RS256", expiresIn: "15m" }
  );

  res.cookie("jwt", token, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
    expires: new Date(Date.now() + (900 * 1000))
  });
  
  res.send(token);
});

const clients = new Map(); // clientId → jwt

app.post("/long-term", (req, res) => {

  // Determine if this is the first registrant
  
  const myjwt = req.cookies.jwt;
  const { clientId } = req.body;
  let parsed;

  if (myjwt) {
    parsed = verifyRating(myjwt); // ⛳ You should handle failure case too
    if (parsed && parsed.clientId) {
      const isExist = clients.has(parsed.clientId);
      if (isExist) {
        const client = clients.get(parsed.clientId);
        if (client) {
          if (!verifyRating(client)) clients.delete(parsed.clientId); // ✅ use `delete` instead of `remove`
          else return res.status(400).json({ success: false, error: "Failed to receive token or invalid cookie" });
        }
      }
    }
  }

  if (clients.has(clientId)) {
    return res.status(409).send("Client already registered");
  }
  

  const token = jwt.sign(
    {
      clientId
    },
    sign_privateKey,
    { algorithm: "RS256", expiresIn: "1d" }
  );

  clients.set(clientId, token);

  res.cookie("jwt_long", token, {
    httpOnly: true,
    sameSite: "None",
    secure: true,
    expires: new Date(Date.now() + (3600 * 1000 * 24 * 180 * 1))
  });
  
  res.status(200).send("OK");
});





app.get("/connect/callback", async (req, res) => {
  const code = req.query.code;
  try {
    const response = await axios.post('https://connect.stripe.com/oauth/token', {
      client_secret: process.env.STRIPE_SECRET_KEY,
      code,
      grant_type: 'authorization_code'
    });

    const stripeUserId = response.data.stripe_user_id;
    const userId = getUserIdFromSessionOrJWT(req); // Implement this part

    // 🔐 Save stripeUserId and mark provider_verified = true
    updateUser(userId, {
      stripeUserId,
      role: "provider_verified"
    });

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Stripe OAuth failed:", err.response?.data || err);
    res.status(500).send("OAuth failed");
  }
});


app.listen(PORT, () => {
  console.log(`✅ Secure server running at http://localhost:${PORT}`);
});
