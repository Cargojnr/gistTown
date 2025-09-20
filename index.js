import express from "express";
import expressLayouts from 'express-ejs-layouts';
import {body, validationResult } from "express-validator";
import bodyParser from "body-parser";
import pg from "pg";
import cors from "cors";
import bcrypt from "bcryptjs";
import session from "express-session";
import pgSession from "connect-pg-simple";
import passport from "passport";
import { Strategy } from "passport-local";
import geoip from "geoip-lite";
import env from "dotenv";
import { Server } from "socket.io";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
import os, { type } from "os";
import { timeStamp } from "console";
// import { WebSocketServer } from "ws";
import fs from "fs";
import http from "http";
// import https from "https"
import multer from "multer";
import Audio from "./models/Audio.js";
import { sendLoginCodeToUser } from "./utils/mailer.js";
import {redis} from "./utils/redis.js"
import {formatCount} from "./utils/format.js"
import { getCurrentUser, ensureAuthenticated} from "./utils/auth.js";
import sequelize from "./db.js";
import rateLimit from "express-rate-limit";
import requestIp from "request-ip";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime.js";
import { console } from "inspector";
dayjs.extend(relativeTime);

const options = {
  key: fs.readFileSync("./key.pem"), // Ensure the file path is correct
  cert: fs.readFileSync("./cert.pem"),
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Store the uploaded files in the "uploads" folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Create a unique filename
  },
});

const upload = multer({ storage });

const app = express();
const server = http.createServer(options, app);
const port = process.env.port || 4000;
const pgSessionStore = pgSession(session);
const io = new Server(server, {
  cors: {
    origin: "*", // Allow frontend connections
    methods: ["GET", "POST"],
  },
});
// const wss = new WebSocket.Server({port});
const saltRounds = 10;
env.config();

const db = new pg.Client({
  user: process.env.DB_USERNAME,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Get the local IP address
const getLocalIPAddress = () => {
  const interfaces = os.networkInterfaces();
  for (const ifaceName in interfaces) {
    for (const iface of interfaces[ifaceName]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address; // Return the first non-internal IPv4 address
      }
    }
  }
  return "localhost"; // Fallback to localhost if no address is found
};

// Load SSL Certificate and Key

db.connect()
  .then(() => {
    console.log("Connected to the database");
  })
  .catch((err) => {
    console.error("Database connection error:", err.stack);
  });


  // app.use(cors({
  //   origin: "https://gisttown.onrender.com", 
  //   credentials: true, // <-- very important for cookies
  // }));

app.use(express.static("public"));
app.use(express.json());
app.use(expressLayouts);
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("layout", "layout");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.set("trust proxy", 1); // trust first proxy (important on Render/Heroku)

app.use(
  session({
    store: new pgSessionStore({
      pool: db,
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      secure: process.env.NODE_ENV === "production", // Ensure cookies are only sent over HTTPS in production
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.locals.formatCount = formatCount;

const activeUsers = new Set();
io.on("connection", (socket) => {
  const userId = parseInt(socket.handshake.query.userId, 10);

  if (!userId) {
    console.error("Missing userId in handshake");
    socket.disconnect(true);
    return;
  }

  // Mark user active
  db.query("UPDATE users SET active_status = true WHERE id = $1", [userId]);
  activeUsers.add(userId);
  socket.join(`user_${userId}`);
  socket.join("audience-stream");

  console.log(`🔗 User ${userId} connected`);

  // Broadcast login
  socket.broadcast.emit("userJoined", userId);


  // 🔌 Disconnect cleanup
  socket.on("disconnect", () => {
    if (activeUsers.has(userId)) {
      db.query("UPDATE users SET active_status = false WHERE id = $1", [userId]);
      activeUsers.delete(userId);
      socket.broadcast.emit("userLeft", userId);
      console.log(`🔌 User ${userId} disconnected`);
    }
  });
});

function resolveAvatarUrl(avatarPath, req) {
  if (!avatarPath) return "/img/default-avatar.png"; // fallback
  // if already absolute URL, return it
  if (/^https?:\/\//i.test(avatarPath)) return avatarPath;
  // otherwise prepend protocol + host
  const prefix = `${req.protocol}://${req.get("host")}`;
  return avatarPath.startsWith("/") ? `${prefix}${avatarPath}` : `${prefix}/${avatarPath}`;
}



// Get Routes 

app.get("/", (req, res) => {
  res.render("home",  { layout: false });
});
app.get("/login", (req, res) => {
  res.render("login",  { layout: false });
});
app.get("/reset", (req, res) => {
  res.render("reset",  { layout: false });
});
app.get("/register", (req, res) => {
  res.render("registration",  { layout: false });
});


//Reusable Routes

// Get user profile
app.get("/user/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    const result = await db.query(
      "SELECT id, username, verified,stealth_mode, profile_picture FROM users WHERE id = $1", [userId]
    );
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});


// List active users
app.get("/active-users", async (req, res) => {
  try {
    const ids = Array.from(activeUsers);
    if (ids.length === 0) return res.json([]);

    const result = await db.query(`
      SELECT id, stealth_mode, username, verified, profile_picture FROM users
      WHERE id = ANY($1::int[])
    `, [ids]);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to get active users" });
  }
});

// Check if a user is active
app.get("/api/active-status/:user", ensureAuthenticated, async (req, res) => {

  try {
    const result = await db.query(
      "SELECT active_status FROM users WHERE id = $1", [req.params.user]
    );
    res.json({ active: result.rows[0]?.active_status || false });
  } catch (err) {
    res.status(500).json({ error: "Error checking active status" });
  }
});

// Get followers
app.get("/eavedrop-status/:targetId", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const audienceId =  user.id;
  const targetId =  req.params.targetId;

  try {
    const check = await db.query(
      "SELECT 1 FROM eavedrops WHERE audience_id = $1 AND target_id = $2",
      [audienceId, targetId]
    );

    if (check.rows.length > 0) {
      return res.json({ status: "eavedropping" });
    } else {
      return res.json({ status: "not_eavedropping" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error" });
  }
});

// routes/checkUsername.js
app.get("/check-username", async (req, res) => {
  try {
    const { username } = req.query;

    if (!username || username.trim().length < 3) {
      return res.status(400).json({ available: false, message: "Too short" });
    }

    const result = await db.query("SELECT id FROM users WHERE username = $1", [username]);

    if (result.rows.length > 0) {
      return res.json({ available: false, message: "Username already taken" });
    }

    return res.json({ available: true, message: "Username available ✅" });
  } catch (err) {
    console.error("Error checking username:", err);
    res.status(500).json({ available: false, message: "Server error" });
  }
});

//Get route fetch post per user
app.get("/fetch-posts/:user", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const { type } = req.query;
  const userId = req.params.user;

    try {
      if (type === "text") {
        const result = await db.query(
          `
        SELECT timestamp, reported, secrets.id, reactions, profile_picture, username, user_id, color, category, secret
        FROM secrets
        JOIN users ON users.id = user_id
        WHERE user_id = $1
        ORDER BY secrets.id DESC
      `,
          [userId]
        );

        
      const secrets = result.rows;

      const bookmarkCounts = await db.query(`
        SELECT secret_id, COUNT(*) AS count
        FROM bookmarks
        WHERE secret_id = ANY($1::int[])
        GROUP BY secret_id
      `, [secrets.map(p => p.id)]);

      const bookmarkMap = {};
      bookmarkCounts.rows.forEach(row => {
        bookmarkMap[row.secret_id] = parseInt(row.count);
      });

      const enrichedPosts = secrets.map(post => ({
        ...post,
        bookmark_count: bookmarkMap[post.id] || 0,
        userId,
      }));

        return res.json({ posts: enrichedPosts });
      } else if (type === "audio") {
        const audioPosts = await Audio.findAll({
          where: { userId },
          order: [["uploadDate", "DESC"]],
        });

        const userInfo = await db.query(
          `SELECT username, profile_picture FROM users WHERE id = $1`,
          [userId]
        );
        const user = userInfo.rows[0];

        const bookmarkCounts = await db.query(`
          SELECT audio_id, COUNT(*) AS count
          FROM bookmarks
          WHERE audio_id = ANY($1::int[])
          GROUP BY audio_id
        `, [audioPosts.map(p => p.id)]);
  
        const bookmarkMap = {};
        bookmarkCounts.rows.forEach(row => {
          bookmarkMap[row.audio_id] = parseInt(row.count);
        });
  

        const formatted = audioPosts.map((audio) => ({
          id: audio.id,
          url: audio.url,
          user_id: audio.userId,
          userId: userId,
          username: user.username,
          profile_pic: avatarUrl,
          timestamp: dayjs(audio.uploadDate).fromNow(),
          bookmark_count: bookmarkMap[audio.id] || 0
        }));

        return res.json({ posts: formatted });
      } else {
        return res.status(400).json({ message: "Invalid type" });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  
});

// Get route fetch comment count per post
app.get("/api/comment-counts", async (req, res) => {
  try {
    // Get counts for secrets
    const secretResult = await db.query(`
      SELECT secrets.id, COUNT(comments.*) AS count
      FROM secrets
      LEFT JOIN comments ON secrets.id = comments.secret_id
      GROUP BY secrets.id
    `);

    // Get counts for audios
    const audioResult = await db.query(`
      SELECT audios.id, COUNT(comments.*) AS count
      FROM audios
      LEFT JOIN comments ON audios.id = comments.audio_id
      GROUP BY audios.id
    `);

    const counts = {};

    secretResult.rows.forEach(row => {
      counts[`text-${row.id}`] = parseInt(row.count);
    });

    audioResult.rows.forEach(row => {
      counts[`audio-${row.id}`] = parseInt(row.count);
    });

    res.json(counts);
  } catch (err) {
    console.error("Error fetching comment counts:", err);
    res.status(500).json({ error: "Error fetching comment counts" });
  }
});


//Get route fetch comment regarding post type and id
app.get("/comment/:type/:id", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const { type, id } = req.params;
  const requestedId = parseInt(id);

  if (isNaN(requestedId)) {
    return res.status(400).json({ error: "Invalid ID" });
  }

  try {
    if (type === "audio") {
    

      const audio = await Audio.findByPk(requestedId);
      if (!audio) return res.status(404).json({ message: "Audio not found" });

      const commentResult = await db.query(
        `SELECT comment, comments.user_id, username,profile_picture, color, comments.id 
         FROM comments 
         JOIN users ON users.id = comments.user_id 
         WHERE audio_id = $1
         ORDER BY comments.id DESC`,
        [requestedId]
      );

      return res.json({
        audio,
        comments: commentResult.rows || [],
        totalComments: commentResult.rowCount,
        noComment: commentResult.rowCount === 0 ? "Be the first to comment" : null,
      });
    }

    if (type === "text") {
      

      const secretQuery = `
        SELECT secret, secrets.id, secrets.user_id, reactions 
        FROM secrets 
        JOIN users ON users.id = user_id 
        WHERE secrets.id = $1 
        ORDER BY secrets.id DESC;
      `;
      const secretResult = await db.query(secretQuery, [requestedId]);
      const data = secretResult.rows[0];

      if (!data) {
        return res.status(404).json({ message: "Secret not found" });
      }

      const commentQuery = `
        SELECT comment, comments.user_id, username, profile_picture,stealth_mode, secret, color, comments.id 
        FROM comments 
        JOIN users ON users.id = comments.user_id 
        JOIN secrets ON secrets.id = secret_id 
        WHERE secrets.id = $1 
        ORDER BY comments.id DESC;
      `;
      const commentResult = await db.query(commentQuery, [requestedId]);


      return res.json({
        secret: data,
        comments: commentResult.rows.length > 0 ? commentResult.rows : null,
        totalComments: commentResult.rows.length,
        noComment: commentResult.rows.length === 0 ? "Share your thoughts." : null,
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
        theme: user.color || "default",
        mode: user.mode || "light",
        reactions: JSON.stringify(data.reactions || {}),
      });
    }

    return res.status(400).json({ error: "Invalid type" });
  } catch (error) {
    console.error("Error fetching comment data:", error);
    res.status(500).json({ error: "Failed to load comment data" });
  }
});

//Get route fetch most engaged post
app.get("/top-discussed", async (req, res) => {
  try {
    // Query to fetch the most discussed secret
    const topDiscussedQuery = `
          SELECT 
  u.profile_picture, 
  s.reactions, 
  s.id, 
  s.secret, 
  COUNT(c.id) AS comment_count, 
  s.user_id
FROM secrets s
LEFT JOIN comments c ON c.secret_id = s.id
JOIN users u ON u.id = s.user_id
GROUP BY s.id, s.secret, s.reactions, s.user_id, u.profile_picture
ORDER BY comment_count DESC, 
         COALESCE((s.reactions->'like'->>'count')::int, 0) DESC
LIMIT 1;


        `;
    const result = await db.query(topDiscussedQuery);

    if (result.rows.length > 0) {
      const topSecret = result.rows[0];

      io.to(`user_${topSecret.user_id}`).emit("new-notification", {
        type: "selected",
        data: {
          id: topSecret.id, // The secret ID
          secret: topSecret.secret,
          userId: topSecret.user_id,
          category: topSecret.category,
        },
      });

      res.json({
        success: true,
        topSecret: topSecret,
        reactions: JSON.stringify(topSecret.reactions || {}),
      });
    } else {
      res.json({ success: false, topSecret: "No trending secret found." });
    }
  } catch (error) {
    console.error("Error fetching top discussed secret:", error);
    res.status(500).json({ error: "Error fetching top discussed secret." });
  }
});


//Get route fetch followers for current user
app.get("/my-eavedrops", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const result = await db.query(
    "SELECT target_id FROM eavedrops WHERE audience_id = $1",
    [user.id]
  );
  res.json(result.rows.map(r => r.target_id));
});



// Render Chat
app.get("/chat",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req);
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userTheme = user.color || "default";
    const mode = user.mode || "light";
    res.render("chat", {
      title: "Connect With Gossipas",
      theme: userTheme,
      mode: mode,
      username: user.username,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
    });

});

// Render Feedback
app.get("/feedback", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req);
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userTheme = user.color || "default";
    const mode = user.mode || "light";
    
    res.render("feedback", {
      title: "Enter Your Feedback",
      theme: userTheme,
      mode: mode,
      username: user.username,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
    });

});


// Render Explore
app.get("/explore", ensureAuthenticated, async(req, res) => {
  const user = getCurrentUser(req);
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const userId = user.id
  try{
    const userResult = await db.query("SELECT * FROM users WHERE id = $1", [userId])

 const userProfile = userResult.rows[0]

 res.render("explore", {
  title: "Explore Your Space",
  userId: user.id,
  verification: user.verified,
  stealthMode : userProfile.stealth_mode,
  username: userProfile.username,
  profilePicture: avatarUrl
})
  }catch(err){
    console.log(err)
  }

});

app.get("/section/:section", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const { section } = req.params;
  const userTheme = user.color || "default";
  const mode = user.mode || "light";
    try {
      
      const result = await db.query(
        "SELECT reported, secrets.id, reactions,profile_picture, stealth_mode, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ",
        [section]
      );
      const usersSecret = result.rows;

      
      // console.log(usersSecret)
      res.render("section", {
        title: "Welcome to a safe space",
        section: usersSecret,
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
        username: user.username,
        theme: userTheme,
        mode: mode,
        reactions: JSON.stringify(
          usersSecret.map((secret) => secret.reactions || {})
        ),
      });
    } catch (err) {
      console.log(err);
    }

});


app.get("/emotional-support", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const userTheme = user.color || "default";
  const mode = user.mode || "light";
    try {
      const keywords = ['love', 'relationship', 'marriage', 'heartbreak', 'breakup', 'advice', 'left me'];

      const query = 
         `
  SELECT reported, secrets.id, reactions, profile_picture, stealth_mode, username, user_id, color, category, secret
  FROM secrets
  JOIN users ON users.id = user_id
  WHERE ${keywords.map((_, i) => `category ILIKE $${i+1}`).join(" OR ")}
  ORDER BY secrets.id DESC
`;

      const values = keywords.map(k => `%${k}%`);

const result = await db.query(query, values);

      const usersSecret = result.rows;
      // console.log(usersSecret)
      res.render("section", {
        title: "Welcome to a safe space",
        section: usersSecret,
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
        username: user.username,
        theme: userTheme,
        mode: mode,
        reactions: JSON.stringify(
          usersSecret.map((secret) => secret.reactions || {})
        ),
      });
    } catch (err) {
      console.log(err);
    }

});


// Render Random
app.get("/random", ensureAuthenticated, async (req, res) => {
const user = getCurrentUser(req);
const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  try {
    const mode = user.mode || "light";
    const result = await db.query(
      "SELECT secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id  ORDER BY secrets.id DESC "
    );
    const usersSecret = result.rows;

    res.render("random", {
      title: "Select Random Confessions",
      randomSecret: usersSecret,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      profilePicture: avatarUrl,
      stealthMode : user.stealth_mode,
      username: user.username,
      mode: mode,
      reactions: JSON.stringify(usersSecret.reactions || {}),
    });
  } catch (err) {
    console.log(err);
  }
});

app.get("/random-secret", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req);
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    try {
      const userTheme = user.color || "default";
      const mode = user.mode || "light";
      const result = await db.query(
        "SELECT secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC "
      );
      const reportResult = await db.query(
        "SELECT reports.status, secrets.id, user_id, category, secret FROM secrets JOIN reports ON secrets.id = reports.secret_id  ORDER BY secrets.id DESC "
      );
      const usersSecret = result.rows;
      const randomSecret = usersSecret[Math.floor(Math.random() * 10)];

      res.json({
        randomSecret: randomSecret,
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        profilePicture: avatarUrl,
        stealthMode : user.stealth_mode,
        username: user.username,
        theme: userTheme,
        mode: mode,
        reactions: JSON.stringify(randomSecret.reactions || {}),
      });
    } catch (err) {
      console.log(err);
    }
});


// Render Subscription
app.get("/subscription", ensureAuthenticated, async(req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  try{
    const result = await db.query("SELECT * FROM users WHERE verified = true")
  
    const subscribers = result.rows
  
    res.render("subscription", {
      subscribers: subscribers,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
      username: user.username,
      title: 'Unlock Premium/Exclusive offers',
    });
  
  }catch{
    console.log(err)
  }
  });
  

// Partial submit form
app.get("/partial-submit", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userTheme = user.color || "default";
    const mode = user.mode || "light";
    console.log(user);

    const formData = {
      title: "Share a Gossip",
      submit: "Submit",
      theme: userTheme,
      mode: mode,
      username: user.username,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
      layout: false
    };

    res.render("partials/submitForm", formData);
});

// Render Submit
app.get("/submit", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userTheme = user.color || "default";
    const mode = user.mode || "light";

    const formData = {
      title: "Share your Gossip",
      submit: "Share",
      theme: userTheme,
      mode: mode,
      username: user.username,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
    };

    res.render("submit", formData);

});



// Render Secret
app.get("/secret/:id", ensureAuthenticated, async (req, res) => {
  const requestedId = parseInt(req.params.id);
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);

  try {
    const userId = user.id
    const userTheme = user.color || "default";
    const mode = user.mode || "light";

    // Fetch secret and reactions in one query
    const secretQuery = `
            SELECT timestamp,stealth_mode,username, profile_picture, secret, secrets.id, secrets.user_id, category, reactions 
            FROM secrets 
            JOIN users ON users.id = user_id 
            WHERE secrets.id = $1 
            ORDER BY secrets.id DESC;
        `;
    const secretResult = await db.query(secretQuery, [requestedId]);
    const data = secretResult.rows[0];

    if (!data) {
      return res
        .status(404)
        .render("not-found", { message: "Secret not found" });
    }

    // Fetch comments
    const commentQuery = `
            SELECT comment, comments.user_id,stealth_mode, username, secret, color, comments.id 
            FROM comments 
            JOIN users ON users.id = comments.user_id 
            JOIN secrets ON secrets.id = secret_id 
            WHERE secrets.id = $1 
            ORDER BY comments.id DESC;
        `;
    const commentResult = await db.query(commentQuery, [requestedId]);
    const commentData = commentResult.rows;

    const relatedQuery = `
        SELECT secrets.id, secret, category, user_id FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC LIMIT 14
        `;

    const relatedResult = await db.query(relatedQuery, [data.category]);
    const relatedGist = relatedResult.rows;

    const userResult = await db.query("SELECT * FROM users WHERE id = $1", [userId])

   const userProfile = userResult.rows[0]

    // Render the page
    res.render("secret", {
      title: `Gist${requestedId}`,
      secret: data,
      comments: commentData.length > 0 ? commentData : null,
      noComment: commentData.length === 0 ? "Share your thoughts." : null,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : userProfile.stealth_mode,
      username: userProfile.username,
      profilePicture: avatarUrl,
      totalComments: commentData.length || null,
      theme: userTheme,
      mode: mode,
      relatedGist,
      reactions: JSON.stringify(data.reactions || {}),
    });
  } catch (error) {
    console.error("Error fetching secret data:", error);
    res
      .status(500)
      .render("error", {
        message: "An error occurred while fetching the secret.",
      });
  }
});



//Render Profile
app.get("/profile", ensureAuthenticated, async (req, res) => {
    const user = getCurrentUser(req);
    const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userId = user.id;
    try {
      const result = await db.query(
        "SELECT active_status,verified,timestamp, reported, secrets.id, reactions,profile_picture, username, bio,user_id, color, category, type, secret FROM secrets JOIN users ON users.id = user_id  WHERE user_id = $1",
        [userId]
      );

      const secrets = result.rows;

      const audioFiles = await Audio.findAll({
        where: { userId },
      });

      const reactionResult = await db.query(
        `SELECT SUM((value->>'count')::int) AS total_reactions
         FROM secrets
         CROSS JOIN LATERAL jsonb_each(reactions) AS r(key, value)
         WHERE user_id = $1`,
        [userId]
      );

      const totalReactions = reactionResult.rows[0].total_reactions || 0;

      const textBookmarkCounts = await db.query(`
        SELECT secret_id, COUNT(*) AS count
        FROM bookmarks
        WHERE secret_id = ANY($1::int[])
        GROUP BY secret_id
      `, [secrets.map(p => p.id)]);

      const textBookmarkMap = {};
      textBookmarkCounts.rows.forEach(row => {
        textBookmarkMap[row.secret_id] = parseInt(row.count);
      });
  
      // Attach bookmark count to each post
      const enrichedTextSecrets = secrets.map(post => ({
        ...post,
        bookmark_count: textBookmarkMap[post.id] || 0
      }));

      const audioBookmarkCounts = await db.query(`
        SELECT audio_id, COUNT(*) AS count
        FROM bookmarks
        WHERE audio_id = ANY($1::int[])
        GROUP BY audio_id
      `, [audioFiles.map(p => p.id)]);

      const audioBookmarkMap = {};
      audioBookmarkCounts.rows.forEach(row => {
        audioBookmarkMap[row.audio_id] = parseInt(row.count);
      });
  
      // Attach bookmark count to each post
      const enrichedAudioSecrets = audioFiles.map(post => ({
        ...post,
        bookmark_count: audioBookmarkMap[post.id] || 0
      }));

      const audienceResult = await db.query(
    "SELECT COUNT(*) FROM eavedrops WHERE target_id = $1",
  [user.id]
   );


   const audienceCount = audienceResult.rows[0].count

      res.render("profile", {
        userId: user.id,
        username: user.username,
        userBio: user.bio,
        email: user.email,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
        avatarAlt: user.avatar_alt ,
        profile: enrichedTextSecrets,
        userAudio: enrichedAudioSecrets,
        audienceCount: audienceCount,
        totalReactions,
        title: "My Profile"
      });
    } catch (err) {
      console.log(err);
    }
});

app.get("/profile/user/:userid", ensureAuthenticated, async (req, res) => {
    const userId = req.params.userid;
    const user = getCurrentUser(req);
    const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    try {
      
      const result = await db.query(
        "SELECT active_status, verified, timestamp, reported, secrets.id, type, reactions,profile_picture, avatar_alt, username,stealth_mode,bio, user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id WHERE user_id = $1 ORDER by secrets.id DESC",
        [userId]
      );

      const secrets = result.rows;

      const userProfile = result.rows;
      const userid = userProfile[0].user_id;
      const username = userProfile[0].username
      const userBio = userProfile[0].bio
      const activeStatus = userProfile.active_status;
      const verification = userProfile[0].verified;
      const userPicture = userProfile[0].profile_picture;
      const userAvatarAlt = userProfile[0].avatar_alt;
      const stealthMode = userProfile[0].stealth_mode;

      const audioFiles = await Audio.findAll({
        where: { userId },
      });

      const reactionResult = await db.query(
        `SELECT SUM((value->>'count')::int) AS total_reactions
         FROM secrets
         CROSS JOIN LATERAL jsonb_each(reactions) AS r(key, value)
         WHERE user_id = $1`,
        [userId]
      );

      const totalReactions = reactionResult.rows[0].total_reactions || 0;
      const totalComments = result.comment;

      const textBookmarkCounts = await db.query(`
        SELECT secret_id, COUNT(*) AS count
        FROM bookmarks
        WHERE secret_id = ANY($1::int[])
        GROUP BY secret_id
      `, [secrets.map(p => p.id)]);

      const textBookmarkMap = {};
      textBookmarkCounts.rows.forEach(row => {
        textBookmarkMap[row.secret_id] = parseInt(row.count);
      });
  
      // Attach bookmark count to each post
      const enrichedTextSecrets = secrets.map(post => ({
        ...post,
        bookmark_count: textBookmarkMap[post.id] || 0
      }));

      const audioBookmarkCounts = await db.query(`
        SELECT audio_id, COUNT(*) AS count
        FROM bookmarks
        WHERE audio_id = ANY($1::int[])
        GROUP BY audio_id
      `, [audioFiles.map(p => p.id)]);

      const audioBookmarkMap = {};
      audioBookmarkCounts.rows.forEach(row => {
        audioBookmarkMap[row.audio_id] = parseInt(row.count);
      });
  
      // Attach bookmark count to each post
      const enrichedAudioSecrets = audioFiles.map(post => ({
        ...post,
        bookmark_count: audioBookmarkMap[post.id] || 0
      }));

        const audienceResult = await db.query(
    "SELECT COUNT(*) FROM eavedrops WHERE target_id = $1",
  [userId]
   );

   const audienceCount = audienceResult.rows[0].count

   const userAvatarUrl = resolveAvatarUrl(userPicture, req);

      res.render("profile", {
        title: stealthMode ? `gossipa${userid} Profile` : username,
        userId: user.id,
        username: user.username,
        verification: user.verified,
        profilePicture: avatarUrl,
        avatarAlt: user.avatar_alt ,
        profileId: userid,
        userName: username,
        userBio: userBio,
        verified: verification,
        stealthMode : stealthMode,
        userPicture: userAvatarUrl,
        userAvatarAlt: userAvatarAlt,
        activeStatus: activeStatus,
        userProfile: enrichedTextSecrets,
        userAudio: enrichedAudioSecrets,
        audienceCount: audienceCount,
        totalComments,
        totalReactions,
      });
    } catch (err) {
      console.log(err);
    }
});


// Render Feeds
app.get("/feeds/:category", ensureAuthenticated, async (req, res) => {
  const { category } = req.params;
  const user = getCurrentUser(req)
  const userTheme = user.color || "default";
  const mode = user.mode || "light";
  try {
    const result = await db.query(
      "SELECT secrets.id, profile_picture, verified,username,user_id, color, secrets.category, secret.type, reactions,  secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ",
      [category]
    );

    const response = result.rows;
    res.json({
      secrets: response,
      theme: userTheme,
      mode: mode,
      reactions: JSON.stringify(response.reactions || {}),
    });
    console.log(`Fetched secrets for category "${category}":`, response);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Failed to fetch secrets" });
  }
});


app.get("/feeds", ensureAuthenticated, async (req, res) => {
    const user = getCurrentUser(req);
    const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const userId = user.id;


    try {
      const userTheme = user.color || "default";
      const mode = user.mode || "light";
      const allUsers = await db.query(
        "SELECT id, verified, username, profile_picture FROM users"
      );

      const trendingQuery = await db.query("SELECT timestamp, verified, username, stealth_mode, profile_picture,secrets.id,secret, type,user_id FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC LIMIT 14")

      const secretsResult = await db.query(`
        SELECT secrets.id, timestamp, reported, verified, reactions,
               profile_picture, stealth_mode, username, user_id, color, category, type, secret
        FROM secrets
        JOIN users ON users.id = user_id
      `);

      const audioPosts = await Audio.findAll({
        order: [["uploadDate", "DESC"]],
      });

      const textPosts = secretsResult.rows.map((secret) => ({
        ...secret,
        type: "text",
        timestamp: new Date(secret.timestamp),
      }));

      const trendingGist = trendingQuery.rows

     // Step 1: Get user IDs from audio posts
const audioUserIds = [...new Set(audioPosts.map(audio => audio.userId))];

// Step 2: Query user info for those IDs
const usersResult = audioUserIds.length
 ? await db.query(
  `SELECT id, username, verified, profile_picture, stealth_mode FROM users WHERE id = ANY($1)`,
  [audioUserIds]
)  
 : {rows: []};
;
const userMap = {};
usersResult.rows.forEach(postUser => {
  userMap[postUser.id] = postUser;
});

// Step 3: Map audio posts with correct user info
const formattedAudio = audioPosts.map((audio) => {
  const postUser = userMap[audio.userId] || {
    username: "unknown",
    verified: false,
    profile_picture: "/img/default-avatar.png",
  };
  return {
    id: audio.id,
    user_id: audio.userId,
    username: postUser.username || "unknown",
    stealthMode: postUser.stealth_mode,
    verified: postUser.verified || false,
    profile_picture: postUser.profile_picture || "/img/default-avatar.png",
    // displayUser: postUser.stealth_mode,
    url: audio.url,
    type: "audio",
    timestamp: new Date(audio.uploadDate),
    reactions: audio.reactions || {} // ✅ Add this line
  };
});


    // Combine and sort by timestamp
    const feeds = [...textPosts, ...formattedAudio].sort(
      (a, b) => b.timestamp - a.timestamp
    );

    res.render("secrets", {
      allUsers: allUsers.rows,
      feeds,
      trendingGist,
      audioPost: formattedAudio, 
      userId,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
      username: user.username,
      theme: userTheme,
      mode,
      title: 'Gossip feeds',
    });
    } catch (err) {
      console.log("Failed to fetch saved gists:", err.message, err.stack);
      res.status(500).json({ error: "Server error", details: err.message }); // prevent infinite loading
    }
});


//Render saved post
app.get("/bookmarked", ensureAuthenticated, async(req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const userId = user.id;

  try {
    // Step 1: Fetch bookmarks for the user
    const bookmarks = await db.query(
      "SELECT * FROM bookmarks WHERE user_id = $1",
      [userId]
    );

    const secretIds = bookmarks.rows
      .filter(b => b.post_type === "text")
      .map(b => b.secret_id);

    const audioIds = bookmarks.rows
      .filter(b => b.post_type === "audio")
      .map(b => b.audio_id);

    // Step 2: Fetch text secrets
    let savedSecrets = [];
    if (secretIds.length > 0) {
      const secretsResult = await db.query(`
        SELECT secrets.id, timestamp, reported, verified, reactions,
               profile_picture, username, user_id, color, category, type, secret
        FROM secrets
        JOIN users ON users.id = user_id
        WHERE secrets.id = ANY($1)
      `, [secretIds]);

      savedSecrets = secretsResult.rows.map(secret => ({
        ...secret,
        type: "text",
        timestamp: new Date(secret.timestamp),
      }));
    }

    // Step 3: Fetch audio posts
    let savedAudios = [];
    if (audioIds.length > 0) {
      const audioPosts = await Audio.findAll({
        where: { id: audioIds },
        order: [["uploadDate", "DESC"]],
      });

      // Get audio post user details
      const audioUserIds = [...new Set(audioPosts.map(a => a.userId))];
      const usersResult = await db.query(
        `SELECT id, username, verified, profile_picture FROM users WHERE id = ANY($1)`,
        [audioUserIds]
      );
      const userMap = {};
      usersResult.rows.forEach(user => userMap[user.id] = user);

      savedAudios = audioPosts.map(audio => {
        const user = userMap[audio.userId] || {};
        return {
          id: audio.id,
          user_id: audio.userId,
          username: user.username || "unknown",
          stealthMode: user.stealth_mode,
          verification: user.verified || false,
          profile_picture: user.profile_picture || "/img/default-avatar.png",
          url: audio.url,
          type: "audio",
          timestamp: new Date(audio.uploadDate),
          reactions: audio.reactions || {}
        };
      });
    }

    const savedFeeds = [...savedSecrets, ...savedAudios].sort((a, b) => b.timestamp - a.timestamp);


    // Final response
    res.render("bookmark", {
      savedFeeds,
      savedAudios,
      userId,
      profilePicture: avatarUrl,
      username: user.username,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      title: "Saved Gists"
    });

  } catch (error) {
    console.error("Failed to fetch saved gists:", error);
    res.status(500).send("Something went wrong loading your saved gists.");
  }
})


//Render Notifications
app.get("/notifications", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    try {
     
      const userTheme = user.color || "default";
      const mode = user.mode || "light";

      // Fetch secrets with timestamp
      const secretResult = await db.query(
        `
                SELECT profile_picture, reactions, secrets.id, username, user_id, type, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE secrets.user_id != $1 
                ORDER BY secrets.id DESC LIMIT 5
            `,
        [user.id]
      );

      const reactionResult = await db.query(
        `
                SELECT profile_picture, reactions, secrets.id, username, user_id,type, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE user_id = $1 AND reactions IS NOT NULL
                ORDER BY secrets.id DESC LIMIT 5
            `,
        [user.id]
      );

      // Fetch comments with timestamp
      const commentsResult = await db.query(
        `
                SELECT comments.user_id, secrets.id, comment, username, color, comments.timestamp
                FROM comments 
                JOIN users ON users.id = comments.user_id 
                JOIN secrets ON secrets.id = secret_id 
                WHERE secrets.user_id = $1 
                ORDER BY comments.id DESC LIMIT 5
            `,
        [user.id]
      );

      // Map through secrets and prepare notifySecret
      const notifySecret = secretResult.rows.map((row) => {
        const reactions = row.reactions || {}; // Default to empty object if reactions are null

        // Create notifyReaction array for each secret
        const notifyReaction = reactionResult.rows.flatMap(row => {
          const reactions = row.reactions || {};
          return Object.keys(reactions).map(type => ({
            id: row.id,
            secret: row.secret,
            type,
            count: reactions[type]?.count || 0,
            timestamp: reactions[type]?.timestamp || row.timestamp,
            notificationType: 'reaction'
          }));
        });

        return {
          ...row,
          reactions,
          notifyReaction, // Array of reaction notifications
          notificationType: "secret",
          timestamp: row.timestamp, // Use secret's timestamp
        };
      });

      

      // Map through comments and prepare notifyComment
      const notifyComment = commentsResult.rows.map((comment) => ({
        ...comment,
        notificationType: "comment",
        timestamp: comment.timestamp, // Use comment's timestamp
      }));

      // Extract reactions from notifySecret
      const notifyReaction = notifySecret
        .flatMap((secret) => secret.notifyReaction) // Flatten all reactions into one array
        .slice(0, 5); // Limit to 5 reactions

      // Combine all notifications
      const combinedNotifications = [
        ...notifySecret,
        ...notifyComment,
        ...notifyReaction,
      ];

      // Sort notifications by timestamp in descending order
      const sortedNotifications = combinedNotifications.sort(
        (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
      );

      // const topNotifications = sortedNotifications.slice(0, 5);

      // Render the notifications page
      res.render("notifications", {
        title: "Notifications",
        heading: `New notifications`,
        comments: notifyComment,
        secrets: notifySecret,
        reactions: notifyReaction,
        notifications: sortedNotifications, // Pass sorted notifications to the client
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
        username: user.username,
        theme: userTheme,
        mode: mode,
      });
    } catch (error) {
      console.log(error);
    }

});

// Render Admin

app.get("/admin/reports", ensureAuthenticated, async (req, res) => {
  try {
    const user = getCurrentUser(req) 
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    const reportsQuery = `
            SELECT reports.id, reports.reported_by, reports.secret_id, reports.comment_id, reports.reason, reports.status, secret AS secret, users.username AS reported_by_username
            FROM reports
            LEFT JOIN secrets ON reports.secret_id = secrets.id
            LEFT JOIN comments ON reports.comment_id = comments.id
            LEFT JOIN users ON reports.reported_by = users.id
            ORDER BY reports.created_at DESC;
        `;
    const result = await db.query(reportsQuery);
    const reports = result.rows;

    res.render("./admin/admin-reports", {
      reports,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      profilePicture: avatarUrl,
      layout: false
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).render("error", { message: "Error fetching reports" });
  }
});

app.get("/admin/reviews", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req) 
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const userTheme = user.color || "default";
  const mode = user.mode || "light";
  try {
    const reviewsQuery = `
            SELECT *, username
            FROM feedbacks JOIN users oN users.id = feedbacks.user_id
            ORDER BY feedbacks.id DESC;
        `;
    const result = await db.query(reviewsQuery);
    const reviews = result.rows;

    var count = 1;

    res.render("./admin/admin-reviews", {
      reviews,
      theme: userTheme,
      mode: mode,
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      profilePicture: avatarUrl,
      count: count,
      layout: false
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ message: "Error fetching reviews" });
  }
});

app.get("/admin-dashboard", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req) 
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
    try {
      const reviewsQuery = `
            SELECT *, username
            FROM feedbacks JOIN users oN users.id = feedbacks.user_id
            ORDER BY feedbacks.id DESC;
        `;

      const usersQuery = `
            SELECT *
            FROM users 
            ORDER BY users.id DESC;
        `;

      const feedsQuery = `
        SELECT * FROM secrets
        ORDER BY  secrets.id
        `;

      const pendingQuery = `
        SELECT * FROM reports WHERE status = 'pending'
        ORDER BY  reports.id
        `;

      const flaggedQuery = `
        SELECT * FROM reports WHERE status = 'flagged'
        ORDER BY  reports.id
        `;

      const reviewsResult = await db.query(reviewsQuery);
      const usersResult = await db.query(usersQuery);
      const feedsResult = await db.query(feedsQuery);
      const pendingResult = await db.query(pendingQuery);
      const flaggedResult = await db.query(flaggedQuery);

      const reviews = reviewsResult.rows;
      const users = usersResult.rows;
      const feeds = feedsResult.rows;
      const pendingReport = pendingResult.rows;
      const flaggedReport = flaggedResult.rows;

      var count = 1;

      res.render("./admin/admin-dashboard", {
        reviews,
        users,
        feeds,
        pendingReport,
        flaggedReport,
        userId: user.id,
        activeStatus: user.active_status,
        verification: user.verified,
        profilePicture: avatarUrl,
        count: count,
        layout: false
      });
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ message: "Error fetching reviews" });
    }
});



//Post Routes

//Reusable routes 

//Post route save a post
app.post("/bookmark", ensureAuthenticated,  async (req, res) => {
  const user = getCurrentUser(req)
  const userId = user?.id;
  const { postId, postType } = req.body;

  if (!userId) return res.status(401).json({ success: false, message: "Not logged in" });

  try {
    // Check for duplicates
    if(postType === "text"){
      const existing = await db.query(
        "SELECT * FROM bookmarks WHERE user_id = $1 AND secret_id = $2",
        [userId, postId]
      );
  
      if (existing.rows.length > 0) {
        return res.json({ success: false, message: "Already bookmarked" });
      }
  
      await db.query(
        "INSERT INTO bookmarks (user_id, secret_id, post_type) VALUES ($1, $2, $3)",
        [userId, postId, postType]
      );
  
      return res.json({ success: true, message: "Gist bookmarked successfully ✅" });
    } else {
      const existing = await db.query(
        "SELECT * FROM bookmarks WHERE user_id = $1 AND audio_id = $2",
        [userId, postId]
      );
  
      if (existing.rows.length > 0) {
        return res.json({ success: false, message: "Already bookmarked" });
      }
  
      await db.query(
        "INSERT INTO bookmarks (user_id, audio_id, post_type) VALUES ($1, $2, $3)",
        [userId, postId, postType]
      );
  
      return res.json({ success: true, message: "Gist bookmarked successfully ✅" });
    }
    
  } catch (error) {
    console.error("Bookmark error:", error);
    return res.status(500).json({ success: false, message: "Failed to bookmark post" });
  }
});


//Post route follow a profile
app.post("/eavedrop", ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)

  const audienceId = user.id;
  const { targetId } = req.body;

  try {
    const check = await db.query(
      "SELECT * FROM eavedrops WHERE audience_id = $1 AND target_id = $2",
      [audienceId, targetId]
    );

    if (check.rows.length > 0) {
      // Already eavedropping — remove
      await db.query(
        "DELETE FROM eavedrops WHERE audience_id = $1 AND target_id = $2",
        [audienceId, targetId]
      );
      return res.json({ status: "removed" });
    } else {
      // Not yet eavedropping — add
      const result = await db.query(
        "INSERT INTO eavedrops (audience_id, target_id) VALUES ($1, $2) RETURNING *",
        [audienceId, targetId]
      );

      const eavedropResult = result.rows[0];

       io.to(`user_${eavedropResult.target_id}`).emit("new-notification", {
          type: "eavedrop",
          data: {
            id: eavedropResult.id,
            target: eavedropResult.target_id,
            audience: eavedropResult.audience_id,
          },
        });

      return res.json({ status: "added" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

//Post route toggle privacy
app.post("/stealth", ensureAuthenticated,  async (req, res) => {
  const user = getCurrentUser(req)

  const userId = user.id;
  const {stealth} = req.body

  try {
     await db.query(
        "UPDATE users SET stealth_mode = $1 WHERE id = $2 ",
        [stealth, userId]
      );


       io.to(`user_${userId}`).emit("new-notification", {
          type: "stealth",
          data: {
            id: userId,
            status: stealth ? "enabled" : "disabled",
          },
        });

      return res.json({ status: stealth ? "enabled" : "disabled"});
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

const AVATAR_WHITELIST_PREFIXES = ["/img/avatars/", "/uploads/"];

function isAllowedAvatarPath(p) {
  if (!p || typeof p !== "string") return false;
  // must be absolute-path style starting with '/'
  if (!p.startsWith("/")) return false;
  // normalize to remove .. etc
  const normalized = path.posix.normalize(p);
  return AVATAR_WHITELIST_PREFIXES.some(prefix => normalized.startsWith(prefix));
}

//Post route update profile
app.post(
  "/update-profile",
  [
    body("username").trim().isLength({ min: 3 }).escape(),
    body("email").isEmail().normalizeEmail(),
    body("bio").trim().isLength({ max: 200 }).blacklist("<>"),
    body("avatar").optional().trim(),
    body("avatarAlt").optional().trim().escape(),
  ], ensureAuthenticated, async (req, res) => {
    const user = getCurrentUser(req)
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.json({ success: false, message: "Invalid input" });
    }

    let { username, email, bio, avatar, avatarAlt } = req.body;
    
    // ✅ Normalize + enforce whitelist for avatar
    if (avatar) {
      if (!avatar.startsWith("/")) avatar = "/" + avatar;
      avatar = path.posix.normalize(avatar);

      if (!isAllowedAvatarPath(avatar)) {
        return res.status(400).json({
          success: false,
          message: "Invalid avatar path",
        });
      }
    } else {
      avatar = user.profile_picture; // keep previous
    }

    if (!avatarAlt) {
      avatarAlt = user.avatar_alt || ""; // fallback if you store alt text
    }
  

    try {
      const userId = user.id; // assuming passport session

      await db.query("UPDATE users SET username = $1, email = $2, bio = $3, profile_picture = $4, avatar_alt = $5 WHERE id = $6",
        [ username, email, bio, avatar, avatarAlt, userId ]
      );

      res.json({
        success: true,
        message: "Profile Updated Successfully",
        user: { userId, username, email, bio, avatar, avatarAlt },
      });
    } catch (err) {
      console.error(err);
      res.json({ success: false, message: "Server error" });
    }
  }
);

//Post route to react to a post text type
app.post("/secret/:id/react",  ensureAuthenticated, async (req, res) => {
  const { type } = req.body; // e.g., "like", "laugh"
  const { id } = req.params;

  try {


    const result = await db.query(
      `UPDATE secrets 
             SET reactions = jsonb_set(
  reactions, 
  $1, 
  jsonb_build_object(
    'count', COALESCE(reactions->$2->>'count', '0')::int + 1, 
    'timestamp', to_jsonb(NOW())
  )::jsonb
)
             WHERE id = $3
             RETURNING reactions, user_id`,
      [`{${type}}`, type, id]
    );

    if (result.rowCount === 1) {
      const { reactions, user_id } = result.rows[0];
      const updatedCount = parseInt(reactions[type].count);
      const milestoneReached = updatedCount === 10;

      io.to(`user_${user_id}`).emit("new-notification", {
        type: "reaction",
        data: {
          id, // The secret ID
          reaction: type, // Only the reacted type
          count: updatedCount, // Updated count for the reaction
          milestone: milestoneReached,
        },
      });

      res.json({ success: true, reactions });
    } else {
      res.status(404).json({ success: false, error: "Secret not found." });
    }
  } catch (error) {
    console.error("Error updating reactions:", error);
    res.status(500).json({ error: "Failed to update reactions." });
  }
});

//Post route to react to a post audio type
app.post("/audio/:id/react",  ensureAuthenticated, async (req, res) => {
  const { type } = req.body; // e.g., "like", "laugh"
  const { id } = req.params;

  try {
    const result = await db.query(
      `UPDATE Audios 
       SET reactions = jsonb_set(
         reactions,
         $1,
         jsonb_build_object(
           'count', COALESCE(reactions->$2->>'count', '0')::int + 1,
           'timestamp', to_jsonb(NOW())
         )::jsonb
       )
       WHERE id = $3
       RETURNING reactions, "userId"`,
      [`{${type}}`, type, id]
    );

    if (result.rowCount === 1) {
      const { reactions, userId } = result.rows[0];
      const updatedCount = parseInt(reactions[type].count);
      const milestoneReached = updatedCount === 10;

      io.to(`user_${userId}`).emit("new-notification", {
        type: "reaction",
        data: {
          id,
          reaction: type,
          count: updatedCount,
          milestone: milestoneReached,
        },
      });

      res.json({ success: true, reactions });
    } else {
      res.status(404).json({ success: false, error: "Audio post not found." });
    }
  } catch (error) {
    console.error("Error updating audio reactions:", error);
    res.status(500).json({ error: "Failed to update reactions." });
  }
});

//Post route to report a post
app.post("/report/secret/:id",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const { reason } = req.body; // The reason for reporting
  const { id } = req.params; // The secret ID

  try {
    // Assuming the user is logged in
    const userId = user.id;

    const result = await db.query(
      `INSERT INTO reports (reported_by, secret_id, reason)
             VALUES ($1, $2, $3) RETURNING *;`,
      [userId, id, reason]
    );

    await db.query(`UPDATE secrets SET reported = $1 WHERE id = $2 `, [
      "true",
      id,
    ]);

    const reportResult = result.rows[0];

    io.emit("report-message", {
      type: "report",
      data: {
        id: reportResult.id, // The secret ID
        reason: reportResult.reason,
        userId: userId,
      },
    });

    res.json({ success: true, reportId: result.rows[0].id });
  } catch (error) {
    console.error("Error reporting secret:", error);
    res.status(500).json({ error: "Failed to report secret" });
  }
});

app.post("/admin/report/:id/resolve",  ensureAuthenticated, async (req, res) => {
  const { id } = req.params;

  try {
    await db.query("UPDATE reports SET status = $1 WHERE id = $2", [
      "resolved",
      id,
    ]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error resolving report:", error);
    res.status(500).json({ error: "Failed to resolve report" });
  }
});

app.post("/admin/report/:id/flag",  ensureAuthenticated, async (req, res) => {
  const { id } = req.params;

  try {
    await db.query("UPDATE reports SET status = $1 WHERE id = $2", [
      "flagged",
      id,
    ]);
    res.json({ success: true });
  } catch (error) {
    console.error("Error flagging report:", error);
    res.status(500).json({ error: "Failed to flag report" });
  }
});


//Post route to live search a post
app.post("/searching",  ensureAuthenticated, async (req, res) => {
  const searchKey = req.body.search;

  if (searchKey.trim() !== "") {
    try {
      const result = await db.query(
        "SELECT username, stealth_mode, verified,secrets.id, secret, profile_picture, timestamp, category, user_id, reactions FROM secrets JOIN users ON user_id = users.id WHERE LOWER(secret) ILIKE $1",
        [`%${searchKey.toLowerCase()}%`]
      );

      if (result.rows.length > 0) {
        res.json({ message: "Results found", searchResults: result.rows });
      } else {
        res.json({ message: "No matching results", searchResults: [] });
      }
    } catch (err) {
      console.error("Search error:", err);
      res.status(500).json({ message: "Server error" });
    }
  } else {
    res.json({ message: "Empty search", searchResults: [] });
  }
});

function highlightMatch(text, keyword) {
  const regex = new RegExp(`(${keyword})`, "gi");
  return text.replace(regex, "<mark>$1</mark>");
}

//Post route to search for a post
app.post("/search",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const { search } = req.body;

  if (!search || search.trim() === "") {
    return res.render("searchResults", { results: [], keyword: "" });
  }

  try {
    const searchTerm = `%${search.toLowerCase()}%`;

    const result = await db.query(
      `SELECT verified,secrets.id, secret, profile_picture, timestamp, category, user_id, reactions FROM secrets JOIN users ON user_id = users.id WHERE LOWER(secret) LIKE $1 ORDER BY id DESC`,
      [searchTerm]
    );

    res.render("searchResults", {
      title: "Search results",
      userId: user.id,
      activeStatus: user.active_status,
      verification: user.verified,
      stealthMode : user.stealth_mode,
      profilePicture: avatarUrl,
      results: result.rows,
      keyword: search,
      highlightMatch,
      // reactions: JSON.stringify(usersSecret.map(secret => secret.reactions || {}))
    });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).send("Internal Server Error");
  }
});

//Post route to share a post either text or audio
app.post("/share", upload.single("audio"),  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const { secret, category, contentType } = req.body; // `contentType` can be 'text' or 'audio'
  const userId = user.id;
    if (!contentType || (contentType !== "text" && contentType !== "audio")) {
      return res
        .status(400)
        .json({ error: 'Invalid content type. Must be "text" or "audio".' });
    }

    try {
      let response;
      let payload;
      let posterSocket;

      if (contentType === "text") {
        // Handle text-based secret
        if (!secret || !category) {
          return res
            .status(400)
            .json({
              error: "Secret and category are required for text content.",
            });
        }

        const result = await db.query(
          "INSERT INTO secrets(secret, user_id, category, type) VALUES($1, $2, $3, $4) RETURNING *;",
          [secret, userId, category, contentType]
        );

        response = result.rows[0];

        const secretResult = await db.query("SELECT username, profile_picture, secret, type, secrets.id, secrets.user_id, reactions FROM secrets JOIN users ON users.id = user_id WHERE secret = $1 ORDER BY secrets.id DESC", [response.secret])

        // When saving audio or text post
   payload = {
  id: secretResult.rows[0].id,
          secret: secretResult.rows[0].secret,
          userId: secretResult.rows[0].user_id,
          username: secretResult.rows[0].username,
          category: secretResult.rows[0].category,
          type: secretResult.rows[0].type,
          avatar: secretResult.rows[0].profile_picture,
          message: ` Gossipa${userId} posted a new ${contentType} gist 📢 `,
};


       // Emit a notification for the new text secret
       for (const [id, socket] of io.sockets.sockets) {
        if (socket.handshake.query.userId !== String(userId)) {
       socket.emit("new-notification", {
        type: "post",
        data: payload,
        });
      }
    }

    // Send success event ONLY to poster
     posterSocket = [...io.sockets.sockets.values()].find(
      s => s.handshake.query.userId === String(userId)
    );
    if (posterSocket) {
      posterSocket.emit("post-success", {
        type: "success",
        data: payload,
      });
    }

      } else if (contentType === "audio") {
        // Handle audio-based secret
        if (!req.file) {
          return res.status(400).json({ error: "No audio file uploaded." });
        }

        const newAudio = await Audio.create({
          filename: req.file.filename,
          path: req.file.path,
          url: `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`,
          userId: userId,
          category: category || "aipudio", // Default category for audio
          type: contentType || "audio",
        });

        response = newAudio;

         payload = {
          id: response.id,
          ...newAudio.toJSON(),
          avatar: user.profile_picture,
          message: ` Gossipa${userId} posted a new ${contentType} gist 📢 `,
        };

        // Emit a notification for the new audio secret
for (const [id, socket] of io.sockets.sockets) {
  if (socket.handshake.query.userId !== String(userId)) {
    socket.emit("new-notification", {
      type: "post",
      data: payload,
    });
  }
}

      // Send success event ONLY to poster
       posterSocket = [...io.sockets.sockets.values()].find(
        s => s.handshake.query.userId === String(userId)
      );
      if (posterSocket) {
        posterSocket.emit("post-success", {
          type: "success",
          data: payload,
        });
      }

      }

 
        const { username, profile_picture } = user;

        io.emit("admin-activity", {
          type: "activity",
          userId,
          username,
          profile_picture,
          message: ` Gossipa${userId} posted a new secret  📢 `,
        });


      res.json({ success: true, data: response, user: user, userId: user.id });
    } catch (error) {
      console.error("Error sharing content:", error);
      res.status(500).json({ error: "Failed to share content." });
    }
 
});

//Post route to edit a post type text
app.post("/edit",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const avatarUrl = resolveAvatarUrl(user.profile_picture, req);
  const secretId = req.body.secId;
    try {
      const userTheme = user.color || "default";
      const mode = user.mode || "light";
      const result = await db.query(
        "SELECT  secrets.id, secret, category FROM secrets JOIN users ON users.id = user_id WHERE secrets.id = $1",
        [secretId]
      );

      const data = result.rows[0];
      res.render("submit", {
        title: "Edit your Gossip",
        submit: "Update",
        secret: data,
        theme: userTheme,
        mode: mode,
        userId: user.id,
        username: user.username,
        activeStatus: user.active_status,
        verification: user.verified,
        stealthMode : user.stealth_mode,
        profilePicture: avatarUrl,
      });
    } catch (error) {
      console.log(error);
      res.status(500).json({ error: "Server error", details: error.message }); // prevent infinite loading
    }
});

//Post route to update a post type text
app.post("/update",  ensureAuthenticated, async (req, res) => {
  const id = req.body.id;
  const updatedSecret = req.body.secret;
  const updatedCategory = req.body.category;
    try {
      const result = await db.query(
        "UPDATE secrets SET secret = $1, category = $2 WHERE id = $3 RETURNING *",
        [updatedSecret, updatedCategory, id]
      );
      const data = result.rows[0];
      console.log(data);
      res.redirect("profile");
    } catch (error) {
      console.log(error);
    }
});

//Post route to delete post type text
app.post("/delete",  ensureAuthenticated, async (req, res) => {
    const postId = req.body.postId;
    try {
      await db.query("DELETE FROM comments WHERE secret_id= $1", [postId]);

      await db.query("DELETE FROM reports WHERE secret_id = $1", [postId]);

      await db.query("DELETE FROM secrets WHERE id = $1", [postId]);

      res.json({success: true, message: "Deleted Successfully" });
    } catch (error) {
      console.log(error);
    }
});

//Post route to delete audio type post
app.post("/audio-delete",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)

    const postId = req.body.postId;
    const userId = user.id;

    try {
      const audio = await Audio.findOne({
        where: { id: postId, userId },
      });

      if (!audio) {
        return res.status(404).json({ error: "Audio file not found" });
      }

      await db.query("DELETE FROM comments WHERE audio_id = $1", [postId]);
      await db.query("DELETE FROM reports WHERE audio_id = $1", [postId]);

      await audio.destroy();
      res.json({success: true, message: "Deleted Successfully" });
    } catch (err) {
      console.error("Error deleting audio file:", err);
      res.status(500).json({ error: "Failed to delete audio file" });
    }
});

//Post route to submit s for post
app.post("/comment/:type", async (req, res) => {
  const { type } = req.params;
  const { id, commentUserId, secretUserId, comment } = req.body;

  const postId = parseInt(id);
  const postUser = parseInt(secretUserId);
  const commentUser = parseInt(commentUserId);

  if (!comment || comment.trim() === "") {
    return res.status(400).json({ success: false, message: "Enter a comment" });
  }

  if (isNaN(postId) || isNaN(commentUser)) {
    return res.status(400).json({ success: false, message: "Invalid ID(s)" });
  }


  try {
    let commentCount;
    let newTotal;

    if (type === "audio") {
      await db.query(
        `INSERT INTO comments (comment, audio_id, user_id) VALUES ($1, $2, $3)`,
        [comment,  postId,  commentUser,]
      );

      
      const result = await db.query(
        `SELECT comment, username,stealth_mode, profile_picture, audios.id, user_id 
         FROM comments 
         JOIN users ON users.id = comments.user_id 
         JOIN audios ON audios.id = audio_id 
         WHERE audios.id = $1 
         ORDER BY comments.id DESC 
         LIMIT 1`,
        [postId]
      );

      const audioCommentResult = await db.query(`
        SELECT audios.id, COUNT(comments.id) AS count
        FROM audios
        LEFT JOIN comments ON audios.id = comments.audio_id
        WHERE audios.id = $1
        GROUP BY audios.id
      `, [postId]);

        commentCount = audioCommentResult.rows[0].count

       newTotal = parseInt(commentCount)

      const newComment = result.rows[0];

      io.to(`user_${postUser}`).emit("new-notification", {
        type: "comment",
        data: {
          id: newComment.id,
          comment: newComment.comment,
          username: newComment.username,
          commentUser: newComment.user_id,
          message: `@gossipa${commentUser} commented on your Gist 📢.`
        },
      });

      io.emit("comment-updated", {
        postId,
          type,
        totalComments: newTotal
        })

        io.emit("new-comment",{
          postId,
          type,
          id: newComment.comment_id,
          comment: newComment.comment,
          username: newComment.username,
          profilePicture: newComment.profile_picture,
          stealthMode: newComment.stealth_mode,
          user_id: newComment.user_id // flatten
        }
      );

      return res.json({ success: true, comment: newComment});
    }

    if (type === "text") {
      await db.query(
        `INSERT INTO comments (comment, secret_id, user_id) VALUES ($1, $2, $3)`,
        [comment,  postId, commentUser]
      );

      const result = await db.query(
        `SELECT comments.id AS comment_id, comment, username,stealth_mode, profile_picture, secret, secrets.id, comments.user_id 
         FROM comments 
         JOIN users ON users.id = comments.user_id 
         JOIN secrets ON secrets.id = secret_id 
         WHERE secrets.id = $1 
         ORDER BY comments.id DESC 
         LIMIT 1`,
        [postId]
      );

      const textCommentResult = await db.query(`
        SELECT secrets.id, COUNT(comments.id) AS count
        FROM secrets
        LEFT JOIN comments ON secrets.id = comments.secret_id
        WHERE secrets.id = $1
        GROUP BY secrets.id
      `, [postId]);

       commentCount = textCommentResult.rows[0].count

       newTotal = parseInt(commentCount)
      

      const newComment = result.rows[0];

      io.to(`user_${postUser}`).emit("new-notification", {
        type: "comment",
        data: {
          id: newComment.comment_id,
          comment: newComment.comment,
          username: newComment.username,
          commentUser: newComment.user_id,
          message: `@gossipa${commentUser} commented on your Gist 📢.`
        },
      });

      io.emit("comment-updated", {
        postId,
          type,
        totalComments: newTotal
        })

      io.emit("new-comment",{
          postId,
          type,
          id: newComment.comment_id,
  comment: newComment.comment,
  username: newComment.username,
  profilePicture: newComment.profile_picture,
  stealthMode: newComment.stealth_mode,
  user_id: newComment.user_id // flatten
        }
      );

      return res.status(200).json({ success: true, comment: newComment, message: "Thoughts shared to the public."});
    }

    return res.status(400).json({ success: false, message: "Invalid comment type" });
  } catch (error) {
    console.error("Error saving comment:", error);
    res.status(500).json({ success: false, message: "Error saving comment" });
  }
});


//Post route to fetch a comment translation
app.post("/translate", express.json(),  ensureAuthenticated, async (req, res) => {
  const { text, targetLang } = req.body;

  if (!text) return res.status(400).json({ error: "No text provided." });

  try {
    // Mock translation (replace with real API call)
    const translated = `[${targetLang}] ${text}`;
    res.json({ translated });
  } catch (err) {
    console.error("Translation error:", err);
    res.status(500).json({ error: "Translation failed." });
  }
});

//Post route to submit review
app.post("/review",  ensureAuthenticated, async (req, res) => {
  const user = getCurrentUser(req)
  const review = req.body.review;
  const rating = req.body.rating;
  const idea = req.body.idea;
    try {
      await db.query(
        "INSERT INTO feedbacks(review, rating, idea, user_id) VALUES($1, $2, $3, $4)",
        [review, rating, idea, user.id]
      );

      res.json({ message: "Your review is being Submitted succesfully" });
    } catch (err) {
      console.log(err);
      res.json({
        message: "Error occurred submitting your review. Try again!",
      });
    }
});


app.post("/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/login");
      });
    });
  });

  //Post route to find account before password reset
app.post("/find-account", async (req, res) => {
  const findAccount = req.body.findAccount;
  if (findAccount !== "") {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE LOWER(email) = $1",
        [findAccount.toLowerCase()]
      );
      const user = result.rows[0];
      res.render("reset", { foundUser: user, layout: false });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.render("reset", {
      message: "Enter email linked to account",
      foundUser: null,
    });
  }
});


//Post route to reset password
app.post("/reset", async (req, res) => {
  const newPassword = req.body.newPassword;
  const confirmPassword = req.body.confirmPassword;
  const foundUserId = req.body.id;

  try {
    if (newPassword !== "" && confirmPassword !== "") {
      if (newPassword === confirmPassword) {
        bcrypt.hash(newPassword, saltRounds, async (err, hash) => {
          if (err) {
            console.log("Error hashing passwords:", err);
          } else {
            const result = await db.query(
              "UPDATE users SET password = $1 WHERE id = $2 RETURNING *",
              [hash, foundUserId]
            );
            const user = result.rows[0];
            console.log(result);
            req.login(user, (err) => {
              console.log(err);
              res.redirect("feeds");
            });
          }
        });
      } else {
        res.render;
      }
    } else {
    }
  } catch (error) {
    console.log(error);
  }
});

  
//Post route to register account
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;
  const avatar = req.body.selectedAvatarInput
  const avatarAlt = req.body.selectedAvatarAlt
  try {
    const checkResult = await db.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (checkResult.rows.length > 0) {
      res.render("register", {
        message: `Username ${username} already exists. Try logging in.`,
      });
    } else {
      //Password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing passwords:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users(profile_picture, avatar_alt, username, email, password) VALUES($1, $2, $3, $4, $5) RETURNING *",
            [avatar, avatarAlt,username, email, hash]
          );
          const user = result.rows[0];
          req.login({id: user.id}, (err) => {
            console.log(err);
            res.redirect("feeds");
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.get("/debug-session", (req, res) => {
  res.json({
    isAuth: req.isAuthenticated(),
    session: req.session,
    user: req.user
  });
});


//Post route to login to account
app.post("/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ error: "Invalid credentials" });
  
      // req.login({id: user.id}, (err) => {
      //   if (err) return next(err);

      //   if (user.needsVerification) {
      //     // Store user in session temporarily
      //     req.session.tempUserId = user.id;
  
      //     return res.json({ needsVerification: true });
      //   }
  
      //   // ✅ Fully logged in user
      //   // return res.json({ redirect: "/feeds" });
      // });

      req.login({id: user.id}, (err) => {
        if (err) return next(err);
        req.session.isVerified = true;
        delete req.session.tempUserId; // Clean up session
        return res.json({ redirect: "/feeds" });

      });
    })(req, res, next);
  });

   //Post route to verify OTP 
const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // limit each IP to 5 requests
  message: { error: "Too many attempts. Try again in 10 mins." },
});

app.post("/verify-code", verifyLimiter, async (req, res, next) => {
    const userId = req.session.tempUserId;
    const { code } = req.body;
  
    if (!userId) {
      return res.status(400).json({ error: "Session expired. Please log in again." });
    }
  
    try {
      const result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);
      const user = result.rows[0];
  
      if (!user || !user.login_code || !user.login_code_expires) {
        return res.status(400).json({ error: "Verification code missing." });
      }
  
      const now = new Date();
      if (user.login_code !== code || new Date(user.login_code_expires) < now) {
        return res.status(401).json({ error: "Invalid or expired code." });
      }

      console.log(code)
  
      // Invalidate the code
      await db.query(
        "UPDATE users SET login_code = NULL, login_code_expires = NULL WHERE id = $1",
        [userId]
      );
  
      // Log successful login
      const ip = req.ip;
      const userAgent = req.headers["user-agent"];
      await db.query(
        "INSERT INTO login_audit (user_id, ip_address, user_agent, timestamp) VALUES ($1, $2, $3, NOW())",
        [userId, ip, userAgent]
      );
  
      // Complete login
      // req.login({id: user.id}, (err) => {
      //   if (err) return next(err);
      //   req.session.isVerified = true;
      //   delete req.session.tempUserId; // Clean up session
      //   return res.json({ redirect: "/feeds" });

      // });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Internal error." });
    }
  });

  
passport.use(
  new Strategy({ passReqToCallback: true }, async function verify(
    req,
    username,
    password,
    cb
  ) {
    try {
      const ip = requestIp.getClientIp(req); // Make sure 'request-ip' is installed and imported
      const location = geoip.lookup(ip);

      const result = await db.query("SELECT * FROM users WHERE username = $1", [
        username,
      ]);
      if (result.rows.length === 0)
        return cb(null, false, { message: "User not found" });

      const user = result.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(password, storedHashedPassword, async (err, isMatch) => {
        if (err) return cb(err);
        if (!isMatch) return cb(null, false, { message: "Incorrect password" });

        // ✅ Generate 2FA code
        const verificationCode = Math.floor(
          100000 + Math.random() * 900000
        ).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

        // ✅ Store code in DB
        await db.query(
          "UPDATE users SET login_code = $1, login_code_expires = $2 WHERE id = $3",
          [verificationCode, expiresAt, user.id]
        );

        console.log("Sending code to:", verificationCode, user.email);
        await sendLoginCodeToUser(user, verificationCode, ip, location);
        console.log("Code sent successfully");

        // ✅ Forward user to verification step
        return cb(null,{id: user.id,needsVerification: !req.session.isVerified });
      });
    } catch (error) {
      console.error("Login 2FA error:", error);
      return cb(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    // merge DB user with the flag from session
    cb(null, user);
  } catch (err) {
    cb(err, null);
  }
});

// Sync database models
sequelize
  .sync({ force: false })
  .then(() => {
    console.log("Database synced!");
  })
  .catch((error) => {
    console.error("Error syncing database:", error);
  });

server.listen(port, "0.0.0.0", () => {
  const localIP = getLocalIPAddress();
  console.log(`Server started on http://${localIP}:${port}`);
});
