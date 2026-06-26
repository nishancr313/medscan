require('dotenv').config({ path: __dirname + '/.env' });

const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']); // 🔥 FIX

console.log("🚀 Starting MedScan Server...");
console.log("ENV CHECK:", process.env.MONGO_URI);

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// ================== MONGODB CONNECTION ==================
console.log("🔄 Connecting to MongoDB...");

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected successfully'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });
// ================== SCHEMAS ==================

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  age: Number,
  phone: String,
  guardian: String,
  guardianPhone: String,
  meds: [
    {
      name: String,
      compartment: Number, // compartment/slot number in the dispenser box, e.g. 1, 2, 3
      dose: Number,
      timings: [String],   // exact times like "08:00", "14:00", "21:00"
      rfidTag: String      // RFID UID string from ESP32, e.g. "A1B2C3D4"
    }
  ]
});

const User = mongoose.model('User', userSchema);

// Dose Log Schema
const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  date: String,
  medIndex: Number,
  taken: Number
});

const DoseLog = mongoose.model('DoseLog', logSchema);

// ================== LIVE SCAN TRACKER (for frontend polling) ==================
// Keeps the most recent scan per user in memory so the dashboard can poll
// '/last-scan' every few seconds and detect a brand-new scan without sockets.
const lastScanByUser = {}; // { userId: { medIndex, medName, compartment, taken, total, at } }

// ================== AUTH MIDDLEWARE ==================
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ================== ROUTES ==================

// Health Check
app.get('/', (req, res) => {
  res.send('✅ MedScan API running');
});

// Register
app.post('/register', async (req, res) => {
  try {
    const { username, password, name, age, phone, guardian, guardianPhone, meds } = req.body;

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const normalizedMeds = (meds || []).map(m => ({
      ...m,
      compartment: m.compartment !== undefined && m.compartment !== '' ? Number(m.compartment) : null
    }));

    const user = await User.create({
      username,
      password: hashedPassword,
      name,
      age,
      phone,
      guardian,
      guardianPhone,
      meds: normalizedMeds
    });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        username: user.username,
        name: user.name,
        meds: user.meds,
        age: user.age,
        phone: user.phone,
        guardian: user.guardian,
        guardianPhone: user.guardianPhone
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Incorrect password' });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        username: user.username,
        name: user.name,
        meds: user.meds,
        age: user.age,
        phone: user.phone,
        guardian: user.guardian,
        guardianPhone: user.guardianPhone
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Forgot Password
app.post('/forgot', async (req, res) => {
  try {
    const { username, newPassword } = req.body;

    const user = await User.findOne({username});
    if (!user) return res.status(400).json({ error: 'User not found' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: '✅ Password reset successful' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Profile
app.get('/profile', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

// Log Dose
app.post('/dose', auth, async (req, res) => {
  try {
    const { date, medIndex, taken } = req.body;

    let log = await DoseLog.findOne({
      userId: req.user.id,
      date,
      medIndex
    });

    if (log) {
      log.taken = taken;
      await log.save();
    } else {
      await DoseLog.create({
        userId: req.user.id,
        date,
        medIndex,
        taken
      });
    }

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get Logs
app.get('/doses', auth, async (req, res) => {
  const logs = await DoseLog.find({ userId: req.user.id });

  const formatted = {};
  logs.forEach(l => {
    if (!formatted[l.date]) formatted[l.date] = {};
    formatted[l.date][l.medIndex] = l.taken;
  });

  res.json(formatted);
});

// RFID Scan — matches by rfidTag scanned from ESP32
app.post('/rfid-scan', async (req, res) => {
  try {
    const { rfidTag } = req.body;

    if (!rfidTag) return res.status(400).json({ error: 'rfidTag is required' });

    // Search all users for a med with this RFID tag
    const user = await User.findOne({ 'meds.rfidTag': rfidTag });
    if (!user) return res.status(404).json({ error: 'No medicine linked to this RFID tag' });

    const medIndex = user.meds.findIndex(m => m.rfidTag === rfidTag);
    const med = user.meds[medIndex];

    const today = new Date().toISOString().split('T')[0];

    let log = await DoseLog.findOne({
      userId: user._id,
      date: today,
      medIndex
    });

    const updatedDose = Math.min((log?.taken || 0) + 1, med.dose);

    if (log) {
      log.taken = updatedDose;
      await log.save();
    } else {
      await DoseLog.create({
        userId: user._id,
        date: today,
        medIndex,
        taken: updatedDose
      });
    }

    res.json({
      success: true,
      taken: updatedDose,
      total: med.dose,
      medicine: med.name,
      compartment: med.compartment ?? null,
      patient: user.name,
      username: user.username
    });

    // Remember this as the latest scan for this user (for dashboard polling)
    lastScanByUser[user._id.toString()] = {
      medIndex,
      medName: med.name,
      compartment: med.compartment ?? null,
      taken: updatedDose,
      total: med.dose,
      date: today,
      at: Date.now()
    };

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Last Scan — frontend polls this every few seconds to detect a fresh RFID scan
// without needing WebSockets. Returns null if there's no scan or it's stale.
app.get('/last-scan', auth, (req, res) => {
  const scan = lastScanByUser[req.user.id];
  if (!scan) return res.json({ scan: null });

  // Consider scans older than 2 minutes as stale so old scans don't keep "popping up"
  if (Date.now() - scan.at > 2 * 60 * 1000) {
    return res.json({ scan: null });
  }

  res.json({ scan });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});