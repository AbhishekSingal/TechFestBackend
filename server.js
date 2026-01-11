const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

// --- CHANGE 1: PRO CORS CONFIG ---
// This allows your Vercel frontend to talk to this backend
// Nuclear CORS: Allow everything explicitly
app.use(
  cors({
    origin: true, // This tells the server to reflect the request origin
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
    ],
  })
);

// Manual Pre-flight Handler (Safari needs this)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With, Accept"
  );
  res.header("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

// --- CHANGE 2: SAFARI PRE-FLIGHT FIX ---
// Safari sends an OPTIONS request before POST. We must handle it.
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// 1. Database Connection
mongoose
  .connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000, // If DB doesn't connect in 5s, it will error out instead of hanging
  })
  .then(() => console.log("✅ Tryst DB Connected"))
  .catch((err) => {
    console.error("❌ DB Error:", err);
    // Important: Don't kill the process, let the server stay up to show the error
  });

// 2. Database Schemas
const UserSchema = new mongoose.Schema({
  name: String,
  entryNo: { type: String, unique: true },
  password: { type: String, required: true },
  registeredEvents: [Number],
});

const User = mongoose.model("User", UserSchema);

// 3. Auth Routes
app.post("/api/register", async (req, res) => {
  const { name, entryNo, password } = req.body;
  if (!name || !entryNo || !password)
    return res.status(400).json({ error: "All fields required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, entryNo, password: hashedPassword });
    res.status(201).json({ message: "User Created" });
  } catch (err) {
    res.status(400).json({ error: "Entry No already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { entryNo, password } = req.body;
  try {
    const user = await User.findOne({ entryNo });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "24h",
      }); // Token expiry is good practice
      res.json({
        token,
        name: user.name,
        registeredEvents: user.registeredEvents,
      });
    } else {
      res.status(401).json({ error: "Invalid Credentials" });
    }
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// 4. Booking Route
app.post("/api/book", async (req, res) => {
  const { token, eventId } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Use { new: true } to get the updated document if needed
    await User.findByIdAndUpdate(decoded.id, {
      $addToSet: { registeredEvents: eventId },
    });
    res.json({ message: "Registered Successfully" });
  } catch (err) {
    res.status(401).json({ error: "Unauthorized or Session Expired" });
  }
});

// --- CHANGE 3: DYNAMIC PORT ---
// Railway/Render will provide their own port. 5001 is the fallback.
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
