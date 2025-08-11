import bodyParser from "body-parser";
import axios from "axios";
import express from "express";
import env from "dotenv";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import multer from "multer";
import fs from "fs";
import nodemailer from "nodemailer";

import pg from "pg";
import { Client } from "pg";

const { Pool } = pg;
const app = express();


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));
app.use(express.static("views"));


env.config();

// Database connection setup

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const db = new Pool({
	connectionString: process.env.DATABASE_URL, // your external DB URL
	ssl: { rejectUnauthorized: false } // required for some external DBs
});

db.connect()
	.then(() => console.log("Connected to PostgreSQL database"))
	.catch((err) => {
		console.error("Database connection error:", err.message);
		process.exit(1);
	});

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", "views");


// Basic root route

// Basic root route with user data collection and theme cookie

app.get("/", async (req, res) => {
	// Collect useful user data
	const userIP = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
	const userAgent = req.headers["user-agent"];

	// Set a default theme cookie if not present
	if (!req.cookies.theme) {
		res.cookie("theme", "dark", { maxAge: 30 * 24 * 60 * 60 * 1000 }); // 30 days
	}
	console.log("User data collected:", { userIP, userAgent });

	// Example: Query the database for demonstration (can be removed/modified)
	let dbStatus = "";
	try {
		const result = await db.query("SELECT NOW() as now");
		dbStatus = `DB Connected, Time: ${result.rows[0].now}`;
	} catch (err) {
		dbStatus = `DB Error: ${err.message}`;
	}

	// Fetch projects and images
	let projects = [];
	try {
		const projResult = await db.query("SELECT * FROM projects ORDER BY id DESC");
		for (const proj of projResult.rows) {
			const imgResult = await db.query("SELECT * FROM project_images WHERE projectid = $1", [proj.id]);
			proj.images = imgResult.rows;
			proj.thumbnail = imgResult.rows.find(img => img.type === "thumbnail");
			proj.otherImages = imgResult.rows.filter(img => img.type === "normal");
			projects.push(proj);
		}
	} catch (err) {
		// Optionally log error
		projects = [];
	}

	// Pass user data and db status to the view
	res.render("index.ejs", {
		userIP,
		userAgent,
		theme: req.cookies.theme || "dark",
		dbStatus,
		projects // Always pass projects
	});
});

// Route to serve CV PDF
app.get('/cv', (req, res) => {
	 console.log("CV requested by user:", req.headers["user-agent"]);
	 res.sendFile(path.join(__dirname, 'public', 'omranCV.pdf'));
});


// Sign in route (compare entered password with hashed password)
app.post('/signin', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
	console.log("Sign in attempt by user:", { username });
    if (result.rows.length === 0) {
      return res.status(401).send('Invalid username or password');
	  console.log("Sign in attempt failed:", { username });
    }
    const user = result.rows[0];
    // Compare entered password with stored hash
    const match = await bcrypt.compare(password, user.password);
	console.log("Sign in attempt:", { username, match });
    if (match) {
      // Render admin dashboard after successful sign in
      res.render('admin.ejs', { username });
    } else {
      res.status(401).send('Invalid username or password');
    }
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/signin', (req, res) => {
  console.log("Sign in page requested by user:", req.headers["user-agent"]);
  res.render('signin.ejs');
});

// Configure multer for file uploads to public folder
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/"); // Save all images to public/uploads
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Ensure uploads folder exists
if (!fs.existsSync("public/uploads")) {
  fs.mkdirSync("public/uploads", { recursive: true });
}

// POST route to create admin
app.post('/create-admin', async (req, res) => {
  try {
    const username = 'admin';
    const plainPassword = 'omrankaadan12ert!';

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);

    // Insert into users table
    const query = `
      INSERT INTO users (username, password)
      VALUES ($1, $2)
      ON CONFLICT (username) DO NOTHING
    `;
    await db.query(query, [username, hashedPassword]);

    res.status(200).send('Admin user created (or already exists)');
  } catch (err) {
    console.error('Error inserting admin:', err);
    res.status(500).send('Error creating admin user');
  }
});

// Add project route
app.post('/admin/add-project', upload.fields([
  { name: 'thumbnail', maxCount: 1 },
  { name: 'images', maxCount: 10 }
]), async (req, res) => {
  const { title, description, finishedby, techstack } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO project (title, description, finishedby, techstack) VALUES ($1, $2, $3, $4) RETURNING id',
      [title, description, finishedby, techstack]
    );
    const projectId = result.rows[0].id;
    // Save thumbnail
    if (req.files['thumbnail']) {
      const thumb = req.files['thumbnail'][0];
      await db.query(
        'INSERT INTO images (url, type, projectid) VALUES ($1, $2, $3)',
        ["/uploads/" + thumb.filename, "thumbnail", projectId]
      );
    }
    // Save other images
    if (req.files['images']) {
      for (const img of req.files['images']) {
        await db.query(
          'INSERT INTO images (url, type, projectid) VALUES ($1, $2, $3)',
          ["/uploads/" + img.filename, "normal", projectId]
        );
      }
    }
    res.redirect('/admin/projects');
  } catch (err) {
    res.status(500).send('Error adding project: ' + err.message);
  }
});

// Route to serve projects as JSON (for API or AJAX)
app.get('/projects', async (req, res) => {
  let projects = [];
  try {
    const projResult = await db.query("SELECT * FROM project ORDER BY id DESC");
    for (const proj of projResult.rows) {
      const imgResult = await db.query("SELECT * FROM images WHERE projectid = $1", [proj.id]);
      proj.images = imgResult.rows;
      proj.thumbnail = imgResult.rows.find(img => img.type === "thumbnail");
      proj.otherImages = imgResult.rows.filter(img => img.type === "normal");
      // Ensure tech_stack field is present
      proj.tech_stack = proj.tech_stack || proj.techstack || '';
      projects.push(proj);
      console.log("Project fetched:", proj);
    }
    return res.json(projects);
  } catch (err) {
    return res.status(500).json({ error: 'Error fetching projects' });
  }
});

// Email sending route
app.post('/send-email', async (req, res) => {
  const { email, message } = req.body;
  try {
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS // Use an app password for security
      }
    });
    await transporter.sendMail({
      from: email,
      to: 'kaadanomran@gmail.com',
      subject: 'Portfolio Contact Form',
      text: message
    });
    res.send('<h2>Email sent successfully!</h2><a href="/">Back to Home</a>');
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).send('<h2>Failed to send email. Please try again later.</h2><pre>' + err.message + '</pre><a href="/">Back to Home</a>');
  }
});

// Start the server
const PORT = process.env.PORT;
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
