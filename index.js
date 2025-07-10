import express from "express";
import expressLayouts from 'express-ejs-layouts';
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import session from "express-session";
import pgSession from "connect-pg-simple";
import passport from "passport";
import { Strategy } from "passport-local";
import crypto from "crypto";
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
import sequelize from "./db.js";
import rateLimit from "express-rate-limit";
import requestIp from "request-ip";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime.js";
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
  // connectionString: process.env.DATABASE_URL,
  //   ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
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

app.use(express.static("public"));
app.use(express.json());
app.use(expressLayouts);
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("layout", "layout");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(
  session({
    store: new pgSessionStore({
      pool: db,
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      secure: process.env.NODE_ENV === "production", // Ensure cookies are only sent over HTTPS in production
      sameSite: "strict",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

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

  // 🔴 Stream Start / Update
  socket.on("live-gist", async ({ content }) => {
    if (typeof content !== "string" || content.length > 2000) return;

    const sanitizedContent = content.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    try {
      await redis.set(`live_gist_${userId}`, sanitizedContent, { ex: 60 });

      await db.query(`
        INSERT INTO live_streams (user_id, content)
        VALUES ($1, $2)
        ON CONFLICT (user_id)
        DO UPDATE SET content = $2, updated_at = NOW(), is_active = true
      `, [userId, sanitizedContent]);

      const result = await db.query(
        "SELECT profile_picture, verified FROM users WHERE id = $1", [userId]
      );

      socket.broadcast.emit("live-gist-started", { userId, sanitizedContent });

      socket.to("audience-stream").emit("receive-live-gist", {
        userId,
        content: sanitizedContent,
        profilePicture: result.rows[0].profile_picture,
        verification: result.rows[0].verified,
        timestamp: Date.now(),
      });

    } catch (err) {
      console.error("Error saving live gist:", err);
    }
  });

  // 🧍 Listener joins someone’s stream
  socket.on("join-live-gist", async ({ streamUserId }) => {
    try {
      const result = await db.query(
        "SELECT profile_picture FROM users WHERE id = $1", [userId]
      );

      const avatarUrl = result.rows[0]?.profile_picture;

      if (avatarUrl) {
        io.emit("listener-joined", {
          streamUserId,
          listenerId: userId,
          avatarUrl,
        });
      }
    } catch (err) {
      console.error("Error fetching listener avatar:", err);
    }
  });

  // 🛑 End Stream
  socket.on("end-live-gist", async () => {
    try {
      const content = await redis.get(`live_gist_${userId}`);
      const endedAt = Date.now();

      await redis.del(`live_gist_${userId}`);

      await db.query(`
        UPDATE live_streams SET is_active = false, updated_at = NOW()
        WHERE user_id = $1
      `, [userId]);

      await redis.set(`ended_gist_${userId}`, JSON.stringify({ content, endedAt }), { ex: 86400 });

      io.emit("remove-live-gist", { userId, lastContent: content, endedAt });
    } catch (err) {
      console.error("Error ending stream:", err);
    }
  });

  // ✅ Save or discard stream post-ending
  socket.on("post-stream-decision", async ({ action }) => {
    try {
      const key = `ended_gist_${userId}`;
      const endedData = await redis.get(key);
      if (!endedData) return;

      const { content } = JSON.parse(endedData);

      if (action === "save") {
        await db.query(`
          INSERT INTO story_streams (user_id, content, created_at, expires_at)
          VALUES ($1, $2, NOW(), NOW() + interval '24 hours')
        `, [userId, content]);
      }

      await redis.del(key);

      socket.emit("story-save-result", { success: true, saved: action === "save" });
    } catch (err) {
      console.error("Error in post-stream-decision:", err);
      socket.emit("story-save-result", { success: false });
    }
  });

  // 👀 View tracking
  socket.on("story-viewed", async ({ storyId }) => {
    try {
      await db.query(`INSERT INTO story_views (story_id, viewer_id) VALUES ($1, $2)`, [storyId, userId]);
      await db.query(`UPDATE story_streams SET views = views + 1 WHERE id = $1`, [storyId]);
    } catch (err) {
      console.error("Failed to log story view:", err);
    }
  });

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

// Get user profile
app.get("/user/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    const result = await db.query(
      "SELECT id, username, verified, profile_picture FROM users WHERE id = $1", [userId]
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
      SELECT id, username, verified, profile_picture FROM users
      WHERE id = ANY($1::int[])
    `, [ids]);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to get active users" });
  }
});

// Check if a user is active
app.get("/api/active-status/:user", async (req, res) => {
  if (!req.isAuthenticated?.()) return res.status(401).json({ active: false });

  try {
    const result = await db.query(
      "SELECT active_status FROM users WHERE id = $1", [req.params.user]
    );
    res.json({ active: result.rows[0]?.active_status || false });
  } catch (err) {
    res.status(500).json({ error: "Error checking active status" });
  }
});

// Get currently active live streams
app.get("/api/live-streams", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT u.id AS user_id, u.username, u.verified, u.profile_picture, s.content, s.updated_at
      FROM live_streams s
      JOIN users u ON u.id = s.user_id
      WHERE s.is_active = true
      ORDER BY s.updated_at DESC
    `);

    res.json(result.rows.map(stream => ({
      userId: stream.user_id,
      username: stream.username,
      content: stream.content,
      profilePicture: stream.profile_picture,
      verification: stream.verified,
      timestamp: stream.updated_at.getTime(),
    })));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch active streams" });
  }
});

// Fetch single live stream
app.get("/api/live-stream/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(`
      SELECT content, started_at, updated_at FROM live_streams
      WHERE user_id = $1 AND is_active = true
    `, [userId]);

    if (result.rows.length === 0) return res.status(404).json({ error: "No live stream found" });

    const user = await db.query("SELECT id, profile_picture, verified FROM users WHERE id = $1", [userId]);

    res.json({ stream: result.rows[0], user: user.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch ended stream backup
app.get("/api/ended-stream/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const cached = await redis.get(`ended_gist_${userId}`);
    if (!cached) return res.status(404).json({ error: "No ended stream found" });

    const data = JSON.parse(cached);
    const user = await db.query("SELECT id, profile_picture, verified FROM users WHERE id = $1", [userId]);

    res.json({
      content: data.content,
      endedAt: data.endedAt,
      user: user.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch ended stream" });
  }
});

// Get all current stories
app.get("/api/stories", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT s.user_id, u.username, u.profile_picture, u.verified, s.content, s.created_at
      FROM story_streams s
      JOIN users u ON u.id = s.user_id
      WHERE s.expires_at > NOW()
      ORDER BY s.created_at DESC
    `);

    res.json(result.rows.map(story => ({
      userId: story.user_id,
      username: story.username,
      content: story.content,
      profilePicture: story.profile_picture,
      verified: story.verified,
      createdAt: story.created_at,
    })));
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stories" });
  }
});




app.get("/profile", async (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user.id;
    try {
      const result = await db.query(
        "SELECT active_status,verified,timestamp, reported, secrets.id, reactions,profile_picture, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id  WHERE user_id = $1",
        [req.user.id]
      );

      const audioFiles = await Audio.findAll({
        where: { userId },
      });

      const userDetails = result.rows;

      res.render("profile", {
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        verification: req.user.verified,
        username: req.user.username,
        profile: userDetails,
        userAudio: audioFiles,
      });
    } catch (err) {
      console.log(err);
    }
  }
});

app.get("/profile/amebo/:user", async (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.params.user;
    try {
      const result = await db.query(
        "SELECT active_status, verified, timestamp, reported, secrets.id, reactions,profile_picture, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id WHERE user_id = $1 ORDER by secrets.id DESC",
        [userId]
      );

      const userProfile = result.rows;
      const userid = userProfile[0].user_id;
      const activeStatus = userProfile.active_status;
      const verification = userProfile[0].verified;
      const userPicture = userProfile[0].profile_picture;

      const audioFiles = await Audio.findAll({
        where: { userId },
      });

      const totalReactions = result.reactions;
      const totalComments = result.comment;

      res.render("profile", {
        userId: req.user.id,
        profileId: userid,
        verification: verification,
        userPicture,
        activeStatus: activeStatus,
        profilePicture: req.user.profile_picture,
        userProfile,
        userAudio: audioFiles,
        totalComments,
        totalReactions,
      });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/explore", (req, res) => {
  if(req.isAuthenticated()){
    res.render("explore", {userId: req.user.id,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture})
  } else {
    res.redirect("login")
  }

})

app.get("/random", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const mode = req.user.mode || "light";
      const result = await db.query(
        "SELECT secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id  ORDER BY secrets.id DESC "
      );
      const usersSecret = result.rows;

      res.render("random", {
        randomSecret: usersSecret,
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        username: req.user.username,
        mode: mode,
        reactions: JSON.stringify(usersSecret.reactions || {}),
      });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("login");
  }
});

app.get("/random-secret", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userTheme = req.user.color || "default";
      const mode = req.user.mode || "light";
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
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        username: req.user.username,
        theme: userTheme,
        mode: mode,
        reactions: JSON.stringify(randomSecret.reactions || {}),
      });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("feeds");
  }
});

app.get("/feeds", async (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user.id;
    try {
      const userTheme = req.user.color || "default";
      const mode = req.user.mode || "light";
      const allUsers = await db.query(
        "SELECT id, verified, username, profile_picture FROM users"
      );

      const secretsResult = await db.query(`
        SELECT secrets.id, timestamp, reported, verified, reactions,
               profile_picture, username, user_id, color, category, secret
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

     // Step 1: Get user IDs from audio posts
const audioUserIds = [...new Set(audioPosts.map(audio => audio.userId))];

// Step 2: Query user info for those IDs
const usersResult = await db.query(
  `SELECT id, username, verified, profile_picture FROM users WHERE id = ANY($1)`,
  [audioUserIds]
);
const userMap = {};
usersResult.rows.forEach(user => {
  userMap[user.id] = user;
});


// Step 3: Map audio posts with correct user info
const formattedAudio = audioPosts.map((audio) => {
  const user = userMap[audio.userId] || {
    username: "unknown",
    verified: false,
    profile_picture: "/img/default-avatar.png",
  };
  return {
    id: audio.id,
    user_id: audio.userId,
    username: user.username || "unknown",
    verification: user.verified || false,
    profile_picture: user.profile_picture || "/img/default-avatar.png",
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
      audioPost: formattedAudio, 
      userId,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
      username: req.user.username,
      theme: userTheme,
      mode,
      title: 'Gossip feeds',
    });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("login");
  }
});

app.get("/fetch-posts/:user", async (req, res) => {
  const { type } = req.query;
  const userId = req.params.user;

  if (req.isAuthenticated()) {
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

        return res.json({ posts: result.rows });
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

        const formatted = audioPosts.map((audio) => ({
          id: audio.id,
          url: audio.url,
          user_id: audio.userId,
          username: user.username,
          profile_pic: user.profile_picture,
          timestamp: dayjs(audio.uploadDate).fromNow(),
        }));

        return res.json({ posts: formatted });
      } else {
        return res.status(400).json({ message: "Invalid type" });
      }
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Server error" });
    }
  } else {
    res.redirect("/login");
  }
});

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
      counts[`secret-${row.id}`] = parseInt(row.count);
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


app.get("/chat", async (req, res) => {
  if (req.isAuthenticated()) {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";
    console.log(req.user);
    res.render("chat", {
      theme: userTheme,
      mode: mode,
      username: req.user.username,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/feedback", async (req, res) => {
  if (req.isAuthenticated()) {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";
    console.log(req.user);
    res.render("feedback", {
      theme: userTheme,
      mode: mode,
      username: req.user.username,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/reports", async (req, res) => {
  try {
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
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).render("error", { message: "Error fetching reports" });
  }
});

app.get("/admin/reviews", async (req, res) => {
  const userTheme = req.user.color || "default";
  const mode = req.user.mode || "light";
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
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
      count: count,
    });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ message: "Error fetching reviews" });
  }
});

app.get("/admin-dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
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
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        count: count,
      });
    } catch (error) {
      console.error("Error fetching reports:", error);
      res.status(500).json({ message: "Error fetching reviews" });
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/feeds/:category", async (req, res) => {
  const { category } = req.params;
  const userTheme = req.user.color || "default";
  const mode = req.user.mode || "light";
  try {
    const result = await db.query(
      "SELECT secrets.id, profile_picture, verified,username,user_id, color, secrets.category, reactions,  secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ",
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

app.get("/section/:section", async (req, res) => {
  const { section } = req.params;
  const userTheme = req.user.color || "default";
  const mode = req.user.mode || "light";
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        "SELECT reported, secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ",
        [section]
      );
      const usersSecret = result.rows;
      // console.log(usersSecret)
      res.render("section", {
        section: usersSecret,
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        username: req.user.username,
        theme: userTheme,
        mode: mode,
        reactions: JSON.stringify(
          usersSecret.map((secret) => secret.reactions || {})
        ),
      });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("login");
  }
});

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

app.get("/partial-submit", async (req, res) => {
  if (req.isAuthenticated()) {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";
    console.log(req.user);

    const formData = {
      title: "Share a Gossip",
      submit: "Submit",
      theme: userTheme,
      mode: mode,
      username: req.user.username,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
      layout: false
    };

    res.render("partials/submitForm", formData);
  } else {
    res.redirect("login");
  }
});

app.get("/submit", async (req, res) => {
  if (req.isAuthenticated()) {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";
    console.log(req.user);

    const formData = {
      submit: "Submit",
      theme: userTheme,
      mode: mode,
      username: req.user.username,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
    };

    res.render("submit", formData);
  } else {
    res.redirect("login");
  }
});


app.get("/secret/:id", async (req, res) => {
  const requestedId = parseInt(req.params.id);
  // console.log(requestedId)
  if (!req.isAuthenticated()) {
    return res.render("login");
  }

  try {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";

    // Fetch secret and reactions in one query
    const secretQuery = `
            SELECT timestamp, profile_picture, secret, secrets.id, secrets.user_id, category, reactions 
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
            SELECT comment, comments.user_id, username, secret, color, comments.id 
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

    // Render the page
    res.render("secret", {
      secret: data,
      comments: commentData.length > 0 ? commentData : null,
      noComment: commentData.length === 0 ? "Share your thoughts." : null,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
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

app.get("/more/:id", async (req, res) => {
  const requestedId = parseInt(req.params.id);
  if (!req.isAuthenticated()) {
    return res.render("login");
  }

  try {
    const userTheme = req.user.color || "default";
    const mode = req.user.mode || "light";

    // Fetch secret and reactions in one query
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

    // Fetch comments
    const commentQuery = `
            SELECT comment, comments.user_id, username, secret, color, comments.id 
            FROM comments 
            JOIN users ON users.id = comments.user_id 
            JOIN secrets ON secrets.id = secret_id 
            WHERE secrets.id = $1 
            ORDER BY comments.id DESC;
        `;
    const commentResult = await db.query(commentQuery, [requestedId]);
    const commentData = commentResult.rows;

    // Render the page
    res.json({
      secret: data,
      comments: commentData.length > 0 ? commentData : null,
      noComment: commentData.length === 0 ? "Share your thoughts." : null,
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
      totalComments: commentData.length || null,
      theme: userTheme,
      mode: mode,
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

app.get("/audio/:id/more", async (req, res) => {
  const audioId = parseInt(req.params.id);

  try {
    const audio = await Audio.findByPk(audioId);
    if (!audio) return res.status(404).json({ message: "Audio not found" });

    const comments = await db.query(
      `SELECT comment, comments.user_id, username, color, comments.id 
       FROM comments 
       JOIN users ON users.id = comments.user_id 
       WHERE audio_id = $1
       ORDER BY comments.id DESC`,
      [audioId]
    );

    res.json({
      audio,
      comments: comments.rows,
      noComment: comments.rows.length === 0 ? "Be the first to comment" : null,
    });
  } catch (err) {
    console.error("Audio comments error:", err);
    res.status(500).json({ error: "Failed to load audio comments" });
  }
});

app.get("/comment/:type/:id", async (req, res) => {
  const { type, id } = req.params;
  const requestedId = parseInt(id);

  if (isNaN(requestedId)) {
    return res.status(400).json({ error: "Invalid ID" });
  }

  try {
    if (type === "audio") {
      const audio = await Audio.findByPk(requestedId);
      if (!audio) return res.status(404).json({ message: "Audio not found" });

      const comments = await db.query(
        `SELECT comment, comments.user_id, username, color, comments.id 
         FROM comments 
         JOIN users ON users.id = comments.user_id 
         WHERE audio_id = $1
         ORDER BY comments.id DESC`,
        [requestedId]
      );

      return res.json({
        audio,
        comments: comments.rows,
        totalComments: comments.rows.length,
        noComment: comments.rows.length === 0 ? "Be the first to comment" : null,
      });
    }

    if (type === "text") {
      if (!req.isAuthenticated()) {
        return res.render("login");
      }

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
        SELECT comment, comments.user_id, username, secret, color, comments.id 
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
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        theme: req.user.color || "default",
        mode: req.user.mode || "light",
        reactions: JSON.stringify(data.reactions || {}),
      });
    }

    return res.status(400).json({ error: "Invalid type" });
  } catch (error) {
    console.error("Error fetching comment data:", error);
    res.status(500).json({ error: "Failed to load comment data" });
  }
});



app.post("/secret/:id/react", async (req, res) => {
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

app.post("/audio/:id/react", async (req, res) => {
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


app.post("/report/secret/:id", async (req, res) => {
  const { reason } = req.body; // The reason for reporting
  const { id } = req.params; // The secret ID

  try {
    // Assuming the user is logged in
    const userId = req.user.id;

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
    console.log(reportResult);

    res.json({ success: true, reportId: result.rows[0].id });
  } catch (error) {
    console.error("Error reporting secret:", error);
    res.status(500).json({ error: "Failed to report secret" });
  }
});

app.post("/admin/report/:id/resolve", async (req, res) => {
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

app.post("/admin/report/:id/flag", async (req, res) => {
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

app.get("/notifications", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userTheme = req.user.color || "default";
      const mode = req.user.mode || "light";

      // Fetch secrets with timestamp
      const secretResult = await db.query(
        `
                SELECT profile_picture, reactions, secrets.id, username, user_id, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE user_id != $1 
                ORDER BY secrets.id DESC LIMIT 5
            `,
        [req.user.id]
      );

      const reactionResult = await db.query(
        `
                SELECT profile_picture, reactions, secrets.id, username, user_id, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE user_id = $1 
                ORDER BY secrets.id DESC LIMIT 5
            `,
        [req.user.id]
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
        [req.user.id]
      );

      // Map through secrets and prepare notifySecret
      const notifySecret = secretResult.rows.map((row) => {
        const reactions = row.reactions || {}; // Default to empty object if reactions are null

        // Create notifyReaction array for each secret
        const notifyReaction = Object.keys(reactions).map((reactionType) => ({
          id: row.id,
          secret: row.secret,
          type: reactionType,
          notificationType: "reaction",
          count: reactions[reactionType]?.count || 0, // Safely access count
          timestamp: reactions[reactionType]?.timestamp || row.timestamp, // Use reaction's timestamp or secret's timestamp
        }));

        return {
          ...row,
          reactions,
          notifyReaction, // Array of reaction notifications
          notificationType: "secret",
          timestamp: row.timestamp, // Use secret's timestamp
        };
      });

      const notifyReactions = reactionResult.rows.map((reaction) => ({
        ...reaction,
        type: reaction.type,
        notificationType: "reaction",
        count: reaction[type]?.count || 0, // Safely access count
        timestamp: reaction[type]?.timestamp || reaction.timestamp,
      }));

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
        // ...notifySecret,
        ...notifyReactions,
        ...notifyComment,
        ...notifyReaction,
      ];

      // Sort notifications by timestamp in descending order
      const sortedNotifications = combinedNotifications.sort(
        (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
      );

      const topNotifications = sortedNotifications.slice(0, 5);

      console.log(topNotifications);
      console.log(notifyReactions);
      // Render the notifications page
      res.render("notifications", {
        heading: `New notifications`,
        comments: notifyComment,
        secrets: notifySecret,
        reactions: notifyReaction,
        notifications: sortedNotifications, // Pass sorted notifications to the client
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
        username: req.user.username,
        theme: userTheme,
        mode: mode,
      });
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("login");
  }
});

app.post("/find-account", async (req, res) => {
  const findAccount = req.body.findAccount;
  if (findAccount !== "") {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE LOWER(email) = $1",
        [findAccount.toLowerCase()]
      );
      const user = result.rows[0];
      res.render("reset", { foundUser: user });
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

app.post("/searching", async (req, res) => {
  const searchKey = req.body.search;

  if (searchKey.trim() !== "") {
    try {
      const result = await db.query(
        "SELECT * FROM secrets JOIN users ON user_id = users.id WHERE LOWER(secret) ILIKE $1",
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

app.post("/search", async (req, res) => {
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
      userId: req.user.id,
      activeStatus: req.user.active_status,
      verification: req.user.verified,
      profilePicture: req.user.profile_picture,
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

app.post("/share", upload.single("audio"), async (req, res) => {
  const { secret, category, contentType } = req.body; // `contentType` can be 'text' or 'audio'
  const userId = req.user.id;

  if (req.isAuthenticated()) {
    if (!contentType || (contentType !== "text" && contentType !== "audio")) {
      return res
        .status(400)
        .json({ error: 'Invalid content type. Must be "text" or "audio".' });
    }

    try {
      let response;

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
          "INSERT INTO secrets(secret, user_id, category) VALUES($1, $2, $3) RETURNING *;",
          [secret, userId, category]
        );

        response = result.rows[0];

        // Emit a notification for the new text secret
        io.emit("new-notification", {
          type: "secret",
          data: {
            id: response.id,
            secret: response.secret,
            userId: response.user_id,
            category: response.category,
          },
        });
      } else if (contentType === "audio") {
        // Handle audio-based secret
        if (!req.file) {
          return res.status(400).json({ error: "No audio file uploaded." });
        }

        const newAudio = await Audio.create({
          filename: req.file.filename,
          path: req.file.path,
          url: `/uploads/${req.file.filename}`,
          userId: userId,
          category: category || "audio", // Default category for audio
        });

        response = newAudio;

        // Emit a notification for the new audio secret
        io.emit("new-notification", {
          type: "audio",
          data: {
            id: response.id,
            filename: response.filename,
            url: response.url,
            userId: response.userId,
            category: response.category,
          },
        });
      }
      const user = await db.query(
        "SELECT username, profile_picture FROM users WHERE id = $1",
        [userId]
      );

      if (user.rows.length > 0) {
        const { username, profile_picture } = user.rows[0];

        io.emit("admin-activity", {
          type: "post",
          userId,
          username,
          profile_picture,
          message: `📢 Gossipa${userId} posted a new secret`,
        });
      }

      console.log(response);
      res.json({ success: true, data: response });
    } catch (error) {
      console.error("Error sharing content:", error);
      res.status(500).json({ error: "Failed to share content." });
    }
  } else {
    res.redirect("login");
  }
});

app.post("/edit", async (req, res) => {
  const secretId = req.body.id;
  if (req.isAuthenticated()) {
    try {
      const userTheme = req.user.color || "default";
      const mode = req.user.mode || "light";
      const result = await db.query(
        "SELECT  secrets.id, secret, category FROM secrets JOIN users ON users.id = user_id WHERE secrets.id = $1",
        [secretId]
      );

      const data = result.rows[0];
      res.render("submit", {
        submit: "Update",
        secret: data,
        theme: userTheme,
        mode: mode,
        userId: req.user.id,
        activeStatus: req.user.active_status,
        verification: req.user.verified,
        profilePicture: req.user.profile_picture,
      });
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("login");
  }
});

app.post("/update", async (req, res) => {
  const id = req.body.id;
  const updatedSecret = req.body.secret;
  const updatedCategory = req.body.category;
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        "UPDATE secrets SET secret = $1, category = $2 WHERE id = $3 RETURNING *",
        [updatedSecret, updatedCategory, id]
      );
      const data = result.rows[0];
      console.log(data);
      res.redirect("dashboard");
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("login");
  }
});

app.post("/delete", async (req, res) => {
  if (req.isAuthenticated()) {
    const id = req.body.secId;
    try {
      await db.query("DELETE FROM comments WHERE secret_id= $1", [id]);

      await db.query("DELETE FROM reports WHERE secret_id = $1", [id]);

      await db.query("DELETE FROM secrets WHERE id = $1", [id]);

      res.json({ message: "Deleted Successfully" });
    } catch (error) {
      console.log(error);
    }
  } else {
    res.redirect("login");
  }
});

app.post("/audio-delete", async (req, res) => {
  if (req.isAuthenticated()) {
    const audioId = req.body.id;
    const userId = req.user.id;

    try {
      const audio = await Audio.findOne({
        where: { id: audioId, userId },
      });

      if (!audio) {
        return res.status(404).json({ error: "Audio file not found" });
      }

      await audio.destroy();
      res.json({ message: "Deleted Successfully" });
    } catch (err) {
      console.error("Error deleting audio file:", err);
      res.status(500).json({ error: "Failed to delete audio file" });
    }
  }
});

app.post("/comment", async (req, res) => {
  // const secretId = req.body.id;
  // const comment = req.body.comment;
  const { id, commentUserId, comment } = req.body;

  if (comment != "") {
    try {
      await db.query(
        "INSERT INTO comments(comment, secret_id, user_id) VALUES($1, $2, $3)",
        [comment, id, commentUserId]
      );

      const result = await db.query(
        "SELECT comment, username,secret, secrets.id, secrets.user_id FROM comments JOIN users ON users.id = comments.user_id JOIN secrets ON secrets.id = secret_id WHERE secrets.id = $1 ORDER BY comments.id DESC LIMIT 1",
        [id]
      );
      const newComment = result.rows[0];

      io.emit("new-notification", {
        type: "comment",
        data: {
          id: newComment.id, // The secret ID
          comment: newComment.comment,
          username: newComment.username,
          userId: newComment.user_id,
        },
      });

      res.status(200).json({ success: true });
      // .redirect(`secret/${secretId}` )
    } catch (error) {
      console.log(error);
      //  res.json({success:false, error: 'Failed to add comment'});
      res.status(500).json({ success: false, message: "Error saving comment" });
    }
  } else {
    res.json({ success: false, message: "Enter a comment" });
  }
});

app.post("/comment/audio", async (req, res) => {
  const { comment, audioId } = req.body;
  const userId = req.user.id;

  try {
    await db.query(
      `INSERT INTO comments (comment, user_id, audio_id) VALUES ($1, $2, $3)`,
      [comment, userId, audioId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Error adding audio comment:", err);
    res.status(500).json({ success: false, error: "Failed to post comment" });
  }
});


app.post("/comment/:type", async (req, res) => {
  const { type } = req.params;
  const { id, commentUserId, comment } = req.body;

  const postId = parseInt(id);
  const userId = parseInt(commentUserId);

  if (!comment || comment.trim() === "") {
    return res.status(400).json({ success: false, message: "Enter a comment" });
  }

  if (isNaN(postId) || isNaN(userId)) {
    return res.status(400).json({ success: false, message: "Invalid ID(s)" });
  }


  try {
    if (type === "audio") {
      await db.query(
        `INSERT INTO comments (comment, user_id, audio_id) VALUES ($1, $2, $3)`,
        [comment,  userId, postId]
      );

      return res.json({ success: true });
    }

    if (type === "text") {
      await db.query(
        `INSERT INTO comments (comment, secret_id, user_id) VALUES ($1, $2, $3)`,
        [comment,  postId, userId]
      );

      const result = await db.query(
        `SELECT comment, username, secret, secrets.id, secrets.user_id 
         FROM comments 
         JOIN users ON users.id = comments.user_id 
         JOIN secrets ON secrets.id = secret_id 
         WHERE secrets.id = $1 
         ORDER BY comments.id DESC 
         LIMIT 1`,
        [postId]
      );

      const newComment = result.rows[0];

      io.emit("new-notification", {
        type: "comment",
        data: {
          id: newComment.id,
          comment: newComment.comment,
          username: newComment.username,
          userId: newComment.user_id,
        },
      });

      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ success: false, message: "Invalid comment type" });
  } catch (error) {
    console.error("Error saving comment:", error);
    res.status(500).json({ success: false, message: "Error saving comment" });
  }
});



app.post("/translate", express.json(), async (req, res) => {
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

app.post("/review", async (req, res) => {
  const review = req.body.review;
  const rating = req.body.rating;
  const idea = req.body.idea;
  if (req.isAuthenticated()) {
    try {
      await db.query(
        "INSERT INTO feedbacks(review, rating, idea, user_id) VALUES($1, $2, $3, $4)",
        [review, rating, idea, req.user.id]
      );

      res.json({ message: "Your review is being Submitted succesfully" });
    } catch (err) {
      console.log(err);
      res.json({
        message: "Error occurred submitting your review. Try again!",
      });
    }
  } else {
    res.redirect("/login");
  }
});


app.post("/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/login");
      });
    });
  });
  

app.post("/register", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;
  const color = req.body.color;
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
            "INSERT INTO users(username, email, password, color) VALUES($1, $2, $3, $4) RETURNING *",
            [username, email, hash, color]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
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

app.post("/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ error: "Invalid credentials" });
  
      req.login(user, (err) => {
        if (err) return next(err);
  
        if (user.needsVerification) {
          // Store user in session temporarily
          req.session.tempUserId = user.id;
  
          return res.json({ needsVerification: true });
        }
  
        // ✅ Fully logged in user
        return res.json({ redirect: "/feeds" });
      });
    })(req, res, next);
  });
    
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
      req.login(user, (err) => {
        if (err) return next(err);
        req.session.isVerified = true;
        delete req.session.tempUserId; // Clean up session
        return res.json({ redirect: "/feeds" });

      });
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
        return cb(null, { id: user.id, needsVerification: !req.session.isVerified });
      });
    } catch (error) {
      console.error("Login 2FA error:", error);
      return cb(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
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
