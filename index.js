import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
// import nodemailer from 'nodemailer';
import { Server } from "socket.io";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
import os, { type } from "os";
import { timeStamp } from "console";
// import { WebSocketServer } from "ws";
import fs from "fs"
import http from "http"
// import https from "https"
import multer from "multer";
import Audio from './models/Audio.js';
import sequelize from './db.js';


const options = {
    key: fs.readFileSync("./key.pem"),  // Ensure the file path is correct
    cert: fs.readFileSync("./cert.pem")
};

// import { config } from 'dotenv';

// const environment = process.env.NODE_ENV || 'development';
// const envFile = environment === 'production' ? '.env.production' : '.env';
// config({ path: envFile });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Store the uploaded files in the "uploads" folder
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
        methods: ["GET", "POST"]
    }
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
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address; // Return the first non-internal IPv4 address
            }
        }
    }
    return 'localhost'; // Fallback to localhost if no address is found
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
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(
    session({
        store: new pgSessionStore({
            pool: db,
            createTableIfMissing: true
        }),
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24,
            secure: process.env.NODE_ENV === 'production', // Ensure cookies are only sent over HTTPS in production
            sameSite: 'strict'
        }
    })
);

app.use(passport.initialize());
app.use(passport.session());

// const transporter = nodemailer.createTransport({
//     host: 'smtp.gmail.com',
//     port: 587,
//     secure: false, // true for 465, false for other ports
//     auth: {
//         user: process.env.EMAIL_USER,
//         pass: process.env.EMAIL_PASS,
//     },
// });


// app.enable("trust proxy");
// app.use((req, res, next) => {
//     if (req.secure) return next();
//     res.redirect("http://" + req.headers.host + req.url);
// });


const activeUsers = new Set();
// let connectedUsers = new Set();

io.on('connection', (socket) => {

    const userId = socket.handshake.query.userId;

    if (userId) {
        console.log(`User ${userId} connected`);
        activeUsers.add(userId);
        socket.join(`user_${userId}`); // Join user's private room
        socket.broadcast.emit('userJoined', `~~anonym~~ ${userId} joined`);
    } else {
        console.error('User ID is missing from handshake query');
    }

    // Handle chat messages
    socket.on('message', (data) => {
        console.log(`Message from ${data.user}: ${data.text}`);
        const messageData = { user: data.user, text: data.text, timestamp: new Date() };
        io.emit('message', messageData); // Broadcast message to all
    });

    // Handle typing event
    socket.on('typing', (data) => {
        socket.broadcast.emit('typing', { user: data.user });
    });

    socket.on('stoppedTyping', () => {
        socket.broadcast.emit('stoppedTyping');
    });

    socket.on('disconnect', () => {
        if (userId && activeUsers.has(userId)) {
            console.log(`~~anonym~~ ${userId} disconnected.`);
            activeUsers.delete(userId);
            socket.broadcast.emit('userLeft', `~~anonym~~ ${userId} left`);
        }
    });
});




app.get("/", (req, res) => {
    res.render("home");
});
app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/reset", (req, res) => {
    res.render("reset");
});
app.get("/register", (req, res) => {
    res.render("registration");
});

app.get("/profile", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const result = await db.query("SELECT * FROM users WHERE id = $1", [req.user.id])
            const userDetails = result.rows[0];
            console.log(userDetails.profile_picture)
            res.render("profile", { userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, profile: userDetails });
        } catch (err) {
            console.log(err)
        }
    }

})

app.get("/random", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const mode = req.user.mode || "light"
            const result = await db.query("SELECT secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC ")
            const reportResult = await db.query("SELECT reports.status, secrets.id, user_id, category, secret FROM secrets JOIN reports ON secrets.id = reports.secret_id  ORDER BY secrets.id DESC ")
            const usersSecret = result.rows;
            // const randomSecret =usersSecret;
            // const randomSecret = usersSecret[Math.floor(Math.random() * 10)]
            console.log(reportResult)

            // console.log(usersSecret)
            res.render("random", { randomSecret: usersSecret, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, mode: mode, reactions: JSON.stringify(usersSecret.reactions || {}), })
            // console.log(usersSecret)
        } catch (err) {
            console.log(err)
        }
    } else {
        res.redirect("feeds")
    }
})

app.get("/random-secret", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userTheme = req.user.color || 'default';
            const mode = req.user.mode || "light"
            const result = await db.query("SELECT secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC ")
            const reportResult = await db.query("SELECT reports.status, secrets.id, user_id, category, secret FROM secrets JOIN reports ON secrets.id = reports.secret_id  ORDER BY secrets.id DESC ")
            const usersSecret = result.rows;
            const randomSecret = usersSecret[Math.floor(Math.random() * 10)]
            console.log(reportResult)

            // console.log(usersSecret)
            res.json({ randomSecret: randomSecret, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, theme: userTheme, mode: mode, reactions: JSON.stringify(randomSecret.reactions || {}), })
            console.log(randomSecret)
        } catch (err) {
            console.log(err)
        }
    } else {
        res.redirect("feeds")
    }
})



app.get("/dashboard", async (req, res) => {

    const message = req.session.loginMessage;
    delete req.session.loginMessage;



    console.log(req.user);
    if (req.isAuthenticated()) {
        const userId = req.user.id;

        try {
            const userSecret = await db.query("SELECT timestamp, reactions, secrets.id,secret, secrets.user_id FROM secrets JOIN users ON users.id = user_id WHERE secrets.user_id = $1 ORDER BY secrets.id ASC", [
                req.user.id
            ])

            const audioFiles = await Audio.findAll({
                where: { userId },
            });
            const secrets = userSecret.rows;

            const totalReactions = secrets.reactions
            const totalComments = secrets.comment

            const mode = req.user.mode || "light"

            const trendingQuery = await db.query("SELECT reactions, secrets.id, secret, secrets.user_id FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC LIMIT 14")



            const trendingGist = trendingQuery.rows

            if (secrets.length > 0 || audioFiles.length > 0) {
                res.render("secrets", { heading: "My Gossips🤫", pGrph: null, secret: secrets, userAudio: audioFiles, trendingGist, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, mode: mode, message, dashboard: true, totalPosts: secrets.length, totalComments, totalReactions })
            } else {
                res.render("secrets", { heading: ``, pGrph: "Welcome to the Safe Space, where you can find comfort and anonymous support. Feel free to be an Amebo (i.e share or read gists in a judgment-free zone).", trendingGist, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, mode: mode, message, dashboard: true , totalPosts: 0, totalComments: 0, totalReactions: 0})
            }
        } catch (error) {
            console.log(error)
        }
    } else {
        res.redirect("login")
    }
});

app.get("/feeds", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userTheme = req.user.color || 'default';
            const mode = req.user.mode || "light"
            const result = await db.query("SELECT timestamp, reported, secrets.id, reactions,profile_picture, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id ORDER BY secrets.id DESC ")

            // const reportResult = await db.query("SELECT reports.status, secrets.id, user_id, category, secret FROM secrets JOIN reports ON secrets.id = reports.secret_id  ORDER BY secrets.id DESC ")
            // console.log(reportResult)
            const usersSecret = result.rows;
            // console.log(usersSecret)
            res.render("secrets", { secrets: usersSecret, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, theme: userTheme, mode: mode, reactions: JSON.stringify(usersSecret.map(secret => secret.reactions || {})), })
        } catch (err) {
            console.log(err)
        }
    } else {
        res.redirect("login")
    }
})

app.get("/chat", async (req, res) => {
    if (req.isAuthenticated()) {
        const userTheme = req.user.color || 'default';
        const mode = req.user.mode || "light"
        console.log(req.user)
        res.render("chat", { theme: userTheme, mode: mode, username: req.user.username, userId: req.user.id, profilePicture: req.user.profile_picture })
    } else {
        res.redirect("/login")
    }
})

app.get("/feedback", async (req, res) => {
    if (req.isAuthenticated()) {
        const userTheme = req.user.color || 'default';
        const mode = req.user.mode || "light"
        console.log(req.user)
        res.render("feedback", { theme: userTheme, mode: mode, username: req.user.username, userId: req.user.id, profilePicture: req.user.profile_picture })
    } else {
        res.redirect("/login")
    }
})


app.get('/admin/reports', async (req, res) => {

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

        res.render('./admin/admin-reports', { reports, userId: req.user.id, profilePicture: req.user.profile_picture });
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).render('error', { message: 'Error fetching reports' });
    }
});

app.get('/admin/reviews', async (req, res) => {
    const userTheme = req.user.color || 'default';
    const mode = req.user.mode || "light"
    try {
        const reviewsQuery = `
            SELECT *, username
            FROM feedbacks JOIN users oN users.id = feedbacks.user_id
            ORDER BY feedbacks.id DESC;
        `;
        const result = await db.query(reviewsQuery);
        const reviews = result.rows;

        var count = 1;

        res.render('./admin/admin-reviews', { reviews, theme: userTheme, mode: mode, userId: req.user.id, profilePicture: req.user.profile_picture, count: count });
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ message: 'Error fetching reviews' });
    }
});

app.get('/admin-dashboard', async (req, res) => {
    const userTheme = req.user.color || 'default';
    const mode = req.user.mode || "light"
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

        res.render('./admin/admin-dashboard', { reviews, users, feeds, pendingReport, flaggedReport, theme: userTheme, mode: mode, userId: req.user.id, profilePicture: req.user.profile_picture, count: count });
    } catch (error) {
        console.error('Error fetching reports:', error);
        res.status(500).json({ message: 'Error fetching reviews' });
    }
});




app.get("/feeds/:category", async (req, res) => {
    const { category } = req.params;
    const userTheme = req.user.color || 'default';
    const mode = req.user.mode || "light"
    try {
        const result = await db.query("SELECT secrets.id, username,user_id, color, secrets.category, reactions,  secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ", [
            category
        ])

        const response = result.rows
        res.json({ secrets: response, theme: userTheme, mode: mode, reactions: JSON.stringify(response.reactions || {}) })
        console.log(`Fetched secrets for category "${category}":`, response);
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: 'Failed to fetch secrets' });
    }
});

app.get("/section/:section", async (req, res) => {
    const { section } = req.params;
    const userTheme = req.user.color || 'default';
    const mode = req.user.mode || "light"
    if (req.isAuthenticated()) {

        try {
            const result = await db.query("SELECT reported, secrets.id, reactions, username,user_id, color, category, secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ",
                [section])
            const usersSecret = result.rows;
            // console.log(usersSecret)
            res.render("section", { section: usersSecret, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, theme: userTheme, mode: mode, reactions: JSON.stringify(usersSecret.map(secret => secret.reactions || {})), })
        } catch (err) {
            console.log(err)
        }
    } else {
        res.redirect("login")
    }

})

app.get("/categories/:category", async (req, res) => {
    const { category } = req.params;
    const userTheme = req.user.color || 'default';
    const mode = req.user.mode || "light"
    try {
        const result = await db.query("SELECT reactions, secrets.id, username,user_id, color, secrets.category, secret FROM secrets JOIN users ON users.id = user_id WHERE category = $1 ORDER BY secrets.id DESC ", [
            category
        ])

        const response = result.rows
        res.render("section", { secrets: response, userId: req.user.id, profilePicture: req.user.profile_picture, username: req.user.username, theme: userTheme, mode: mode, reactions: JSON.stringify(response.reactions || {}) })
        console.log(`Fetched secrets for category "${category}":`, response);
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: 'Failed to fetch secrets' });
    }
});

app.get('/top-discussed', async (req, res) => {
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
                }
            })


            res.json({ success: true, topSecret: topSecret, reactions: JSON.stringify(topSecret.reactions || {}) });
        } else {
            res.json({ success: false, topSecret: 'No trending secret found.' });
        }
    } catch (error) {
        console.error('Error fetching top discussed secret:', error);
        res.status(500).json({ error: 'Error fetching top discussed secret.' });
    }
});


app.get("/partial-submit", async (req, res) => {
    if (req.isAuthenticated()) {
        const userTheme = req.user.color || 'default';
        const mode = req.user.mode || "light"
        console.log(req.user)

        const formData = {
            submit: "Submit",
            theme: userTheme,
            mode: mode,
            username: req.user.username,
            userId: req.user.id, profilePicture: req.user.profile_picture
        };

        res.render("partials/submitForm", formData)
    } else {
        res.redirect("login")
    }
})



app.get("/submit", async (req, res) => {
    if (req.isAuthenticated()) {
        const userTheme = req.user.color || 'default';
        const mode = req.user.mode || "light"
        console.log(req.user)

        const formData = {
            submit: "Submit",
            theme: userTheme,
            mode: mode,
            username: req.user.username,
            userId: req.user.id, profilePicture: req.user.profile_picture
        };

        res.render("submit", formData)
    } else {
        res.redirect("login")
    }
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.log(err)
        res.redirect("login");
    })
})

app.get("/secret/:id", async (req, res) => {
    const requestedId = parseInt(req.params.id);
    // console.log(requestedId)
    if (!req.isAuthenticated()) {
        return res.render("login");
    }

    try {
        const userTheme = req.user.color || 'default';
        const mode = req.user.mode || "light";

        // Fetch secret and reactions in one query
        const secretQuery = `
            SELECT secret, secrets.id, secrets.user_id, category, reactions 
            FROM secrets 
            JOIN users ON users.id = user_id 
            WHERE secrets.id = $1 
            ORDER BY secrets.id DESC;
        `;
        const secretResult = await db.query(secretQuery, [requestedId]);
        const data = secretResult.rows[0];

        if (!data) {
            return res.status(404).render("not-found", { message: "Secret not found" });
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
        `

        const relatedResult = await db.query(relatedQuery, [data.category])
        const relatedGist = relatedResult.rows;

        // Render the page
        res.render("secret", {
            secret: data,
            comments: commentData.length > 0 ? commentData : null,
            noComment: commentData.length === 0 ? "Share your thoughts." : null,
            userId: req.user.id, profilePicture: req.user.profile_picture,
            totalComments: commentData.length || null,
            theme: userTheme,
            mode: mode,
            relatedGist,
            reactions: JSON.stringify(data.reactions || {}),
        });
    } catch (error) {
        console.error("Error fetching secret data:", error);
        res.status(500).render("error", { message: "An error occurred while fetching the secret." });
    }
});

app.get("/more/:id", async (req, res) => {
    const requestedId = parseInt(req.params.id);
    // console.log(requestedId)
    if (!req.isAuthenticated()) {
        return res.render("login");
    }

    try {
        const userTheme = req.user.color || 'default';
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
            return res.status(404).render("not-found", { message: "Secret not found" });
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
            userId: req.user.id, profilePicture: req.user.profile_picture,
            totalComments: commentData.length || null,
            theme: userTheme,
            mode: mode,
            reactions: JSON.stringify(data.reactions || {}),
        });
    } catch (error) {
        console.error("Error fetching secret data:", error);
        res.status(500).render("error", { message: "An error occurred while fetching the secret." });
    }
});





app.post('/secret/:id/react', async (req, res) => {
    const { type } = req.body; // e.g., "like", "laugh"
    const { id } = req.params;

    try {
        console.log('Attempting to update reaction:', { type, id });

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

            console.log(`Sending notification to user_${user_id}`, {
                id, reaction: type, count: updatedCount, milestone: milestoneReached
            });

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
            res.status(404).json({ success: false, error: 'Secret not found.' });
        }
    } catch (error) {
        console.error('Error updating reactions:', error);
        res.status(500).json({ error: 'Failed to update reactions.' });
    }
});





app.post('/report/secret/:id', async (req, res) => {
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

        await db.query(`UPDATE secrets SET reported = $1 WHERE id = $2 `, ["true", id])

        const reportResult = result.rows[0]

        io.emit("report-message", {
            type: "report",
            data: {
                id: reportResult.id, // The secret ID
                reason: reportResult.reason,
                userId: userId,
            },
        })
        console.log(reportResult)

        res.json({ success: true, reportId: result.rows[0].id });
    } catch (error) {
        console.error('Error reporting secret:', error);
        res.status(500).json({ error: 'Failed to report secret' });
    }
});


app.post('/admin/report/:id/resolve', async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('UPDATE reports SET status = $1 WHERE id = $2', ['resolved', id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error resolving report:', error);
        res.status(500).json({ error: 'Failed to resolve report' });
    }
});

app.post('/admin/report/:id/flag', async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('UPDATE reports SET status = $1 WHERE id = $2', ['flagged', id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error flagging report:', error);
        res.status(500).json({ error: 'Failed to flag report' });
    }
});



app.get("/notifications", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userTheme = req.user.color || 'default';
            const mode = req.user.mode || "light";

            // Fetch secrets with timestamp
            const secretResult = await db.query(`
                SELECT reactions, secrets.id, username, user_id, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE user_id != $1 
                ORDER BY secrets.id DESC LIMIT 5
            `, [req.user.id]);

            const reactionResult = await db.query(`
                SELECT reactions, secrets.id, username, user_id, secret, timestamp
                FROM secrets 
                JOIN users ON users.id = user_id 
                WHERE user_id = $1 
                ORDER BY secrets.id DESC LIMIT 5
            `, [req.user.id]);

            // Fetch comments with timestamp
            const commentsResult = await db.query(`
                SELECT comments.user_id, secrets.id, comment, username, color, comments.timestamp
                FROM comments 
                JOIN users ON users.id = comments.user_id 
                JOIN secrets ON secrets.id = secret_id 
                WHERE secrets.user_id = $1 
                ORDER BY comments.id DESC LIMIT 5
            `, [req.user.id]);

            // Map through secrets and prepare notifySecret
            const notifySecret = secretResult.rows.map(row => {
                const reactions = row.reactions || {}; // Default to empty object if reactions are null

                // Create notifyReaction array for each secret
                const notifyReaction = Object.keys(reactions).map(reactionType => ({
                    id: row.id,
                    secret: row.secret,
                    type: reactionType,
                    notificationType: 'reaction',
                    count: reactions[reactionType]?.count || 0, // Safely access count
                    timestamp: reactions[reactionType]?.timestamp || row.timestamp // Use reaction's timestamp or secret's timestamp
                }));

                return {
                    ...row,
                    reactions,
                    notifyReaction, // Array of reaction notifications
                    notificationType: 'secret',
                    timestamp: row.timestamp // Use secret's timestamp
                };
            });

            const notifyReactions = reactionResult.rows.map(reaction => ({
                ...reaction,
                type: reaction.type,
                notificationType: 'reaction',
                count: reaction[type]?.count || 0, // Safely access count
                timestamp: reaction[type]?.timestamp || reaction.timestamp
            }))

            // Map through comments and prepare notifyComment
            const notifyComment = commentsResult.rows.map(comment => ({
                ...comment,
                notificationType: 'comment',
                timestamp: comment.timestamp   // Use comment's timestamp
            }));

            // Extract reactions from notifySecret
            const notifyReaction = notifySecret
                .flatMap(secret => secret.notifyReaction) // Flatten all reactions into one array
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

            console.log(topNotifications)
            console.log(notifyReactions)
            // Render the notifications page
            res.render("notifications", {
                heading: `New notifications`,
                comments: notifyComment,
                secrets: notifySecret,
                reactions: notifyReaction,
                notifications: sortedNotifications, // Pass sorted notifications to the client
                userId: req.user.id, profilePicture: req.user.profile_picture,
                username: req.user.username,
                theme: userTheme,
                mode: mode
            });
        } catch (error) {
            console.log(error);
        }
    } else {
        res.redirect("login");
    }
});



// wss.on('connection', ws => {
//     ws.on('message', message => {
//         console.log('recieved', message);
//     });

//     ws.send(JSON.stringify({type: 'notification', message: 'You have a new notification'}));
// })



app.post("/find-account", async (req, res) => {
    const findAccount = req.body.findAccount
    if (findAccount !== "") {
        try {
            const result = await db.query("SELECT * FROM users WHERE LOWER(email) = $1", [
                findAccount.toLowerCase()
            ]);
            const user = result.rows[0];
            res.render("reset", { foundUser: user })
        } catch (err) {
            console.log(err);
        }
    } else {
        res.render("reset", { message: "Enter email linked to account", foundUser: null })
    }
})

app.post("/search", async (req, res) => {
    const searckKey = req.body.search
    if (searckKey !== "") {
        try {
            const result = await db.query("SELECT * FROM secrets WHERE LOWER(secret) = $1", [
                searckKey.toLowerCase()
            ]);
            const searchResult = result.rows[0];
            const searchResults = result.rows

            console.log(searchResult)

            if(result.rows.length > 1) {
                res.json({ message:"Results found", searchResults : searchResults })
            } else {
                res.json({ message:"Result found", searchResult: searchResult})
            }
           
        } catch (err) {
            console.log(err);
        }
    } else {
        res.json({ message: "No result sound", searchResult: null })
    }
})

app.post("/reset", async (req, res) => {
    const newPassword = req.body.newPassword
    const confirmPassword = req.body.confirmPassword
    const foundUserId = req.body.id

    try {
        if (newPassword !== "" && confirmPassword !== "") {
            if (newPassword === confirmPassword) {
                bcrypt.hash(newPassword, saltRounds, async (err, hash) => {
                    if (err) {
                        console.log("Error hashing passwords:", err)
                    } else {
                        const result = await db.query("UPDATE users SET password = $1 WHERE id = $2 RETURNING *", [
                            hash, foundUserId
                        ]);
                        const user = result.rows[0];
                        console.log(result);
                        req.login(user, (err) => {
                            console.log(err);
                            res.redirect("dashboard");
                        })
                    }
                });
            } else {
                res.render
            }
        } else {

        }
    } catch (error) {
        console.log(error)
    }
})

app.post('/share', upload.single('audio'), async (req, res) => {
    const { secret, category, contentType } = req.body; // `contentType` can be 'text' or 'audio'
    const userId = req.user.id;

    if (req.isAuthenticated()) {
        if (!contentType || (contentType !== 'text' && contentType !== 'audio')) {
            return res.status(400).json({ error: 'Invalid content type. Must be "text" or "audio".' });
        }

        try {
            let response;

            if (contentType === 'text') {
                // Handle text-based secret
                if (!secret || !category) {
                    return res.status(400).json({ error: 'Secret and category are required for text content.' });
                }

                const result = await db.query(
                    "INSERT INTO secrets(secret, user_id, category) VALUES($1, $2, $3) RETURNING *;",
                    [secret, userId, category]
                );

                response = result.rows[0];

                // Emit a notification for the new text secret
                io.emit('new-notification', {
                    type: 'secret',
                    data: {
                        id: response.id,
                        secret: response.secret,
                        userId: response.user_id,
                        category: response.category,
                    },
                });
            } else if (contentType === 'audio') {
                // Handle audio-based secret
                if (!req.file) {
                    return res.status(400).json({ error: 'No audio file uploaded.' });
                }

                const newAudio = await Audio.create({
                    filename: req.file.filename,
                    path: req.file.path,
                    url: `/uploads/${req.file.filename}`,
                    userId: userId,
                    category: category || 'audio', // Default category for audio
                });

                response = newAudio;

                // Emit a notification for the new audio secret
                io.emit('new-notification', {
                    type: 'audio',
                    data: {
                        id: response.id,
                        filename: response.filename,
                        url: response.url,
                        userId: response.userId,
                        category: response.category,
                    },
                });
            }

            console.log(response);
            res.json({ success: true, data: response });
        } catch (error) {
            console.error('Error sharing content:', error);
            res.status(500).json({ error: 'Failed to share content.' });
        }
    } else {
        res.redirect("login")
    }
});



app.post("/edit", async (req, res) => {
    const secretId = req.body.id;
    if (req.isAuthenticated()) {
        try {
            const userTheme = req.user.color || 'default';
            const mode = req.user.mode || "light"
            const result = await db.query("SELECT  secrets.id, secret, category FROM secrets JOIN users ON users.id = user_id WHERE secrets.id = $1", [
                secretId
            ]);

            const data = result.rows[0];
            res.render("submit", { submit: "Update", secret: data, theme: userTheme, mode: mode, userId: req.user.id, profilePicture: req.user.profile_picture })
        } catch (error) {
            console.log(error);
        }

    } else {
        res.redirect("login")
    }
});

app.post("/update", async (req, res) => {
    const id = req.body.id;
    const updatedSecret = req.body.secret
    const updatedCategory = req.body.category;
    if (req.isAuthenticated()) {
        try {
            const result = await db.query("UPDATE secrets SET secret = $1, category = $2 WHERE id = $3 RETURNING *", [
                updatedSecret, updatedCategory, id
            ]);
            const data = result.rows[0]
            console.log(data);
            res.redirect("dashboard")
        } catch (error) {
            console.log(error);
        }
    } else {
        res.redirect("login")
    }
})

app.post("/delete", async (req, res) => {
    if (req.isAuthenticated()) {
        const id = req.body.secId
        try {
            await db.query("DELETE FROM comments WHERE secret_id= $1", [
                id
            ])

            await db.query("DELETE FROM reports WHERE secret_id = $1", [
                id
            ])

            await db.query("DELETE FROM secrets WHERE id = $1", [
                id
            ])


            res.json({ message: 'Deleted Successfully' });
        } catch (error) {
            console.log(error)
        }
    } else {
        res.redirect("login")
    }
});

app.post("/audio-delete", async (req, res) => {
    if (req.isAuthenticated()) {
        const audioId = req.body.id
        const userId = req.user.id

        try {
            const audio = await Audio.findOne({
                where: { id: audioId, userId },
            });

            if (!audio) {
                return res.status(404).json({ error: 'Audio file not found' })
            }

            await audio.destroy();
            res.json({ message: 'Deleted Successfully' });
        } catch (err) {
            console.error('Error deleting audio file:', err)
            res.status(500).json({ error: 'Failed to delete audio file' })

        }
    }
});

app.post("/comment", async (req, res) => {
    // const secretId = req.body.id;
    // const comment = req.body.comment;
    const { id, commentUserId, comment } = req.body;

    if (comment != "") {
        try {
            await db.query("INSERT INTO comments(comment, secret_id, user_id) VALUES($1, $2, $3)", [
                comment, id, commentUserId
            ])

            const result = await db.query("SELECT comment, username,secret, secrets.id, secrets.user_id FROM comments JOIN users ON users.id = comments.user_id JOIN secrets ON secrets.id = secret_id WHERE secrets.id = $1 ORDER BY comments.id DESC LIMIT 1", [
                id
            ])
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
            console.log(error)
            //  res.json({success:false, error: 'Failed to add comment'});
            res.status(500).json({ success: false, message: 'Error saving comment' })
        }
    } else {
        res.json({ success: false, message: 'Enter a comment' })
    }
})



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
  


app.post("/reaction", async (req, res) => {
    const reaction = req.body.reaction
    const secretId = req.body.id
    try {
        const result = await db.query("INSERT INTO reactions(reaction, secret_id, user_id) VALUES($1, $2, $3) RETURNING *;",
            [reaction, secretId, req.user.id]
        )
        const response = result.rows;
        console.log(response, secretId)
        res.json(response)

    } catch (err) {
        console.log(err)
    }
})

app.post("/change", async (req, res) => {
    const color = String(req.body.color);
    if (req.isAuthenticated()) {
        try {
            await db.query("UPDATE users SET color = $1 WHERE id = $2;",
                [color, req.user.id]
            )
            console.log(req.user.id, color)
            req.user.color = color
            res.redirect("/dashboard")
        } catch (err) {
            console.log(err);
        }
    } else {
        res.redirect("/login")
    }
})

app.post("/review", async (req, res) => {
    const review = req.body.review;
    const rating = req.body.rating;
    const idea = req.body.idea;
    if (req.isAuthenticated()) {
        try {
            await db.query("INSERT INTO feedbacks(review, rating, idea, user_id) VALUES($1, $2, $3, $4)",
                [review, rating, idea, req.user.id]
            )

            res.json({ message: "Your review is being Submitted succesfully" })
        } catch (err) {
            console.log(err)
            res.json({ message: "Error occurred submitting your review. Try again!" })
        }
    } else {
        res.redirect("/login")
    }
})


app.post("/register", async (req, res) => {
    const username = req.body.username
    const email = req.body.email
    const password = req.body.password
    const color = req.body.color
    try {
        const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [
            username
        ]);

        if (checkResult.rows.length > 0) {
            res.render("register", { message: `Username ${username} already exists. Try logging in.` })
        } else {
            //Password hashing
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error hashing passwords:", err)
                } else {
                    const result = await db.query("INSERT INTO users(username, email, password, color) VALUES($1, $2, $3, $4) RETURNING *", [
                        username, email, hash, color
                    ]);
                    const user = result.rows[0];
                    console.log(result);
                    req.login(user, (err) => {
                        console.log(err);
                        res.redirect("dashboard");
                    })
                }
            })
        }
    } catch (error) {
        console.log(error);
    }

});

app.post("/login", (req, res, next) => {

    passport.authenticate("local", (err, user, info) => {
        if (err) {
            console.log('Authenticate error:', err)
            return next(err);
        }
        if (!user) {
            console.log('User not found, redirecting to login')
            return res.redirect("/login");
        }



        req.logIn(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return next(err);
            }

            const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            const timestamp = new Date().toLocaleString();
            const userEmail = req.body.email;

            // req.session.loginMessage = `You are logged in from IP: ${ip} at ${timestamp}`;

            // const mailOptions = {
            //     from: process.env.EMAIL_USER,
            //     to: userEmail,
            //     subject: 'Login Notification',  // Corrected to lowercase 'subject'
            //     text: `User is logged in from IP: ${ip} at ${timestamp}`,
            // };

            // transporter.sendMail(mailOptions, (error, info) => {
            //     if (error) {
            //         console.error('Error sending email:', error);
            //     } else {
            //         console.log('Email sent:', info.response);
            //     }
            // });

            // console.log(`User is logged in from IP: ${ip} at ${timestamp}`);
            req.session.userId = user.user_id;
            res.redirect("/dashboard");
        });
    })(req, res, next);

    // return res.render("notifications", {loginMessage: `You are logged in from iP: ${ip} at ${timestamp}`, theme: userTheme, username: null, userId: null})
    // return res.redirect("/secrets");
})

// req.logIn(user, (err) => {
//     if(err) {
//         return next(err);
//     }
// (req, res, next);
//     {
//     successRedirect: "/secrets",
//     failureRedirect: "/login",
// }
// });

passport.use(new Strategy(async function verify(username, password, cb) {
    console.log(username)
    try {
        const result = await db.query("SELECT * FROM users WHERE LOWER(username || ' ' || email) LIKE '%' || $1 || '%'", [
            username
        ]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedpassword = user.password;
            bcrypt.compare(password, storedHashedpassword, (err, isMatch) => {
                if (err) {
                    return cb(err);
                }
                if (isMatch) {
                    return cb(null, user);
                } else {
                    console.log('Incorrect password');
                    return cb(null, false);
                }
            });
        } else {
            return cb("User not found")
            // res.render("login", {message: `User not found.`});
        }

    } catch (error) {
        return cb(error);
    }

}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser((user, cb) => {
    cb(null, user);
});

// server.listen(port, '0.0.0.0', () => {
//     console.log(`Server started on port ${process.env.DB_HOST}:${port}`);
// });

// Sync database models
sequelize.sync({ force: false }).then(() => {
    console.log("Database synced!");
}).catch((error) => {
    console.error('Error syncing database:', error);
});

server.listen(port, '0.0.0.0', () => {
    const localIP = getLocalIPAddress();
    console.log(`Server started on http://${localIP}:${port}`);
});