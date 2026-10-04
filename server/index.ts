import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {
  listRecords,
  insertRecord,
  updateRecord,
  deleteRecord,
} from './mongoData';
import 'dotenv/config';
import mongoose from 'mongoose';
import {
  DbUser,
  logActivity,
  getLogs,
  seedDatabase,
  getTableRecords,
  insertTableRecord,
  updateTableRecord,
  deleteTableRecord,
  insertReminderLog,
  getReminderLogs,
  getReminderLogsByTrainee,
  ReminderLog,
  getFallbackCollection,
} from './db';
import {
  authenticate,
  requireAuth,
  requireAdmin,
  hashPassword,
  comparePassword,
  generateToken,
  AuthenticatedRequest,
} from './auth';

export const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 5001;

if (process.env.VERCEL) {
  app.set('trust proxy', 1);
}

function getUsersCollection(): any {
  const mongoDb = mongoose.connection.db;
  if (mongoDb && mongoose.connection.readyState === 1) return mongoDb.collection('users');
  return getFallbackCollection('users');
}

// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(authenticate);

// Request logging (development/demo)
app.use((req: Request, _res: Response, next: NextFunction) => {
  if (req.path.startsWith('/api')) {
    console.log(`[API] ${req.method} ${req.path}`);
  }
  next();
});

// ============================================================================
// Health check
// ============================================================================
app.get('/api/health', async (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    app: 'SkillTrack — Maharashtra Skilling Outcomes',
    database: 'MongoDB Atlas',
    uptime: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// Authentication API
// ============================================================================

// POST /api/auth/register
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { fullName, email, password, confirmPassword, district, phone } = req.body;

    if (!fullName || typeof fullName !== 'string' || fullName.trim().length < 2) {
      res.status(400).json({ error: 'Full name must be at least 2 characters long.' });
      return;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email.trim().toLowerCase())) {
      res.status(400).json({ error: 'Please provide a valid email address.' });
      return;
    }

    if (!password || password.length < 8) {
      res.status(400).json({ error: 'Password must be at least 8 characters long.' });
      return;
    }

    const hasLetter = /[a-zA-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    if (!hasLetter || !hasNumber) {
      res.status(400).json({ error: 'Password must contain both letters and numbers.' });
      return;
    }

    if (password !== confirmPassword) {
      res.status(400).json({ error: 'Passwords do not match.' });
      return;
    }

    const cleanEmail = email.trim().toLowerCase();
    const existing = await getUsersCollection().findOne({ email: cleanEmail });
    if (existing) {
      res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
      return;
    }

    const id = `USR-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password);
    const role = 'user';

    await getUsersCollection().insertOne({
      id,
      fullName: fullName.trim(),
      email: cleanEmail,
      passwordHash,
      role,
      district: district || 'Pune',
      phone: phone || '',
      createdAt: now,
      updatedAt: now,
    });

    const userPayload = {
      id,
      fullName: fullName.trim(),
      email: cleanEmail,
      role: 'user' as const,
      district: district || 'Pune',
      phone: phone || '',
    };

    const token = generateToken(userPayload);
    res.cookie('skilltrack_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    logActivity('USER_REGISTER', 'USER', id, `User registered: ${cleanEmail}`, id, fullName.trim());

    res.status(201).json({
      message: 'Account created successfully!',
      user: userPayload,
      token,
    });
  } catch (e) {
    console.error('Registration error:', e);
    res.status(500).json({ error: 'Failed to create account. Please try again later.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: 'Email and password are required.' });
      return;
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const userRow = (await getUsersCollection().findOne({ email: cleanEmail })) as unknown as DbUser | null;

    if (!userRow || !comparePassword(String(password), userRow.passwordHash)) {
      res.status(401).json({ error: 'Invalid email or password. Please try again.' });
      return;
    }

    const userPayload = {
      id: userRow.id,
      fullName: userRow.fullName,
      email: userRow.email,
      role: userRow.role,
      district: userRow.district || undefined,
      phone: userRow.phone || undefined,
      traineeId: userRow.traineeId || undefined,
    };

    const token = generateToken(userPayload);
    res.cookie('skilltrack_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    logActivity('USER_LOGIN', 'USER', userRow.id, `User logged in: ${userRow.email}`, userRow.id, userRow.fullName);

    res.json({
      message: 'Welcome back!',
      user: userPayload,
      token,
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Sign in failed. Please try again later.' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', async (_req: Request, res: Response) => {
  res.clearCookie('skilltrack_token');
  res.json({ success: true, message: 'Signed out successfully.' });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const user = (await getUsersCollection().findOne(
      { id: req.user!.id },
      { projection: { _id: 0, passwordHash: 0 } }
    )) as unknown as Partial<DbUser> | null;
    if (!user) {
      res.status(404).json({ error: 'User record not found.' });
      return;
    }
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: 'Failed to retrieve profile.' });
  }
});

// PUT /api/auth/profile
app.put('/api/auth/profile', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { fullName, phone, district, oldPassword, newPassword } = req.body;
    const userId = req.user!.id;

    const user = (await getUsersCollection().findOne({ id: userId })) as unknown as DbUser | null;
    if (!user) {
      res.status(404).json({ error: 'User record not found.' });
      return;
    }

    let passwordHash = user.passwordHash;
    if (newPassword) {
      if (!oldPassword || !comparePassword(oldPassword, user.passwordHash)) {
        res.status(400).json({ error: 'Current password is incorrect.' });
        return;
      }
      if (newPassword.length < 8) {
        res.status(400).json({ error: 'New password must be at least 8 characters.' });
        return;
      }
      passwordHash = hashPassword(newPassword);
    }

    const updatedName = fullName && fullName.trim().length >= 2 ? fullName.trim() : user.fullName;
    const updatedPhone = phone !== undefined ? phone : user.phone;
    const updatedDistrict = district !== undefined ? district : user.district;
    const now = new Date().toISOString();

    await getUsersCollection().updateOne(
      { id: userId },
      {
        $set: {
          fullName: updatedName,
          phone: updatedPhone,
          district: updatedDistrict,
          passwordHash,
          updatedAt: now,
        },
      }
    );

    const updatedUser = {
      id: user.id,
      fullName: updatedName,
      email: user.email,
      role: user.role,
      district: updatedDistrict,
      phone: updatedPhone,
      traineeId: user.traineeId,
    };

    logActivity('PROFILE_UPDATE', 'USER', userId, 'User updated profile details', userId, updatedName);

    res.json({ message: 'Profile updated successfully', user: updatedUser });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});

// ============================================================================
// Data Tables API (list / insert / update / delete)
// ============================================================================

const ALLOWED_TABLES = new Set([
  'trainees',
  'employees',
  'trainingPrograms',
  'providers',
  'employers',
  'skills',
  'followups',
]);

// GET /api/data/:table
app.get('/api/data/:table', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { table } = req.params;

  if (!ALLOWED_TABLES.has(table)) {
    res.status(400).json({ error: `Unknown table: ${table}` });
    return;
  }

  try {
    const records = await listRecords(table);
    res.json(records);
  } catch (e) {
    console.error(`Error loading table ${table} from MongoDB:`, e);
    res.status(500).json({ error: `Failed to load table ${table}` });
  }
});

// POST /api/data/:table
app.post('/api/data/:table', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { table } = req.params;

  if (!ALLOWED_TABLES.has(table)) {
    res.status(400).json({ error: `Unknown table: ${table}` });
    return;
  }

  try {
    const record = req.body;
    if (!record || typeof record !== 'object' || typeof record.id !== 'string') {
      res.status(400).json({ error: 'Record must be an object with an id property.' });
      return;
    }

    await insertRecord(table, record);
    logActivity('RECORD_INSERT', table.toUpperCase(), record.id, `Inserted into ${table}`, req.user?.id, req.user?.fullName);
    res.status(201).json({ success: true, record });
  } catch (e) {
    console.error(`Error inserting into MongoDB table ${table}:`, e);
    res.status(500).json({ error: `Failed to insert record into ${table}` });
  }
});


// PUT /api/data/:table/:id
app.put('/api/data/:table/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { table, id } = req.params;

  if (!ALLOWED_TABLES.has(table)) {
    res.status(400).json({ error: `Unknown table: ${table}` });
    return;
  }

  try {
    const updated = await updateRecord(table, id, req.body);
    if (!updated) {
      res.status(404).json({ error: `Record ${id} not found in ${table}` });
      return;
    }

    logActivity('RECORD_UPDATE', table.toUpperCase(), id, `Updated ${table} record ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, record: updated });
  } catch (e) {
    console.error(`Error updating MongoDB table ${table}:`, e);
    res.status(500).json({ error: `Failed to update record in ${table}` });
  }
});

// DELETE /api/data/:table/:id
app.delete('/api/data/:table/:id', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const { table, id } = req.params;

  if (!ALLOWED_TABLES.has(table)) {
    res.status(400).json({ error: `Unknown table: ${table}` });
    return;
  }

  try {
    const deleted = await deleteRecord(table, id);
    if (!deleted) {
      res.status(404).json({ error: `Record ${id} not found in ${table}` });
      return;
    }

    logActivity('RECORD_DELETE', table.toUpperCase(), id, `Deleted from ${table}: ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, message: `Record ${id} deleted from ${table}` });
  } catch (e) {
    console.error(`Error deleting from MongoDB table ${table}:`, e);
    res.status(500).json({ error: `Failed to delete record from ${table}` });
  }
});
// ============================================================================
// Specialized Trainee CRUD API
// ============================================================================

// GET /api/trainees (with search, filter, pagination)
app.get('/api/trainees', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const trainees = await getTableRecords<Record<string, unknown>>('trainees');
    const { search, district, status, page = '1', limit = '10' } = req.query;

    let filtered = trainees;
    if (search && typeof search === 'string' && search.trim()) {
      const q = search.trim().toLowerCase();
      filtered = filtered.filter(
        (t) =>
          String(t.fullName || '').toLowerCase().includes(q) ||
          String(t.id || '').toLowerCase().includes(q) ||
          String(t.district || '').toLowerCase().includes(q)
      );
    }

    if (district && district !== 'all' && typeof district === 'string') {
      filtered = filtered.filter((t) => t.district === district);
    }

    const p = Math.max(1, parseInt(String(page), 10) || 1);
    const l = Math.max(1, Math.min(100, parseInt(String(limit), 10) || 10));
    const total = filtered.length;
    const paginated = filtered.slice((p - 1) * l, p * l);

    res.json({
      trainees: paginated,
      total,
      page: p,
      totalPages: Math.max(1, Math.ceil(total / l)),
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch trainees' });
  }
});

// GET /api/trainees/:id
app.get('/api/trainees/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  const trainees = await getTableRecords<Record<string, unknown>>('trainees');
  const trainee = trainees.find((t) => t.id === id);
  if (!trainee) {
    res.status(404).json({ error: `Trainee ${id} not found` });
    return;
  }
  const employees = await getTableRecords<Record<string, unknown>>('employees');
  const employee = employees.find((e) => e.traineeId === id);
  const followups = (await getTableRecords<Record<string, unknown>>('followups')).filter((f) => f.traineeId === id);

  res.json({ trainee, employee, followups });
});

// GET /api/trainees/check-duplicate
app.get('/api/trainees/check-duplicate', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { phone, fullName, district } = req.query;
    const trainees = await getTableRecords<Record<string, unknown>>('trainees');

    const cleanPhone = typeof phone === 'string' ? phone.replace(/\D/g, '').slice(-10) : '';
    const cleanName = typeof fullName === 'string' ? fullName.trim().toLowerCase() : '';
    const cleanDistrict = typeof district === 'string' ? district.trim().toLowerCase() : '';

    const match = trainees.find((t) => {
      const tPhone = String(t.phone || '').replace(/\D/g, '').slice(-10);
      const tName = String(t.fullName || '').trim().toLowerCase();
      const tDist = String(t.district || '').trim().toLowerCase();

      if (cleanPhone && cleanPhone.length >= 10 && tPhone === cleanPhone) {
        return true;
      }
      if (cleanName && cleanName.length > 2 && tName === cleanName && cleanDistrict && tDist === cleanDistrict) {
        return true;
      }
      return false;
    });

    if (match) {
      res.json({
        duplicate: true,
        match: {
          id: match.id,
          fullName: match.fullName,
          phone: match.phone,
          district: match.district,
          programId: match.programId,
        },
      });
    } else {
      res.json({ duplicate: false });
    }
  } catch (e) {
    res.status(500).json({ error: 'Failed to check duplicate' });
  }
});

// POST /api/trainees (Create)
app.post('/api/trainees', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const input = req.body;
    if (!input.fullName || input.fullName.trim().length < 2) {
      res.status(400).json({ error: 'Full name is required (at least 2 characters).' });
      return;
    }
    if (!input.programId) {
      res.status(400).json({ error: 'Training program is required.' });
      return;
    }
    if (!input.providerId) {
      res.status(400).json({ error: 'Training provider is required.' });
      return;
    }

    const programs = await getTableRecords<{ id: string; durationHours: number; assessedSkills: string[]; sector?: string }>('trainingPrograms');
    const program = programs.find((p) => p.id === input.programId) || {
      id: input.programId,
      durationHours: 320,
      assessedSkills: ['Trade fundamentals', 'Safety practices'],
      sector: 'Not recorded',
    };

    const count = (await getTableRecords('trainees')).length + 1;
    const seq = String(20000 + count).padStart(5, '0');
    const traineeId = `ST-2026-MH-${seq}`;
    const today = new Date().toISOString().slice(0, 10);

    const traineeRecord = {
      id: traineeId,
      fullName: input.fullName.trim(),
      gender: input.gender || 'Female',
      age: Number(input.age) || 22,
      phone: input.phone || `+91 ${Math.floor(9000000000 + Math.random() * 999999999)}`,
      email: input.email || `${input.fullName.toLowerCase().replace(/[^a-z]/g, '')}.${seq.slice(-3)}@maha-skills.org`,
      eshramUan: typeof input.eshramUan === 'string' ? input.eshramUan.replace(/\D/g, '').slice(0, 12) || undefined : undefined,
      district: input.district || 'Pune',
      division: input.division || 'Pune',
      category: input.category || 'General',
      education: input.education || '12th Pass / ITI',
      trainingYear: input.trainingYear || '2024-25',
      programId: input.programId,
      providerId: input.providerId,
      batchId: `B-${seq.slice(-3)}`,
      enrolmentDate: today,
      consentStatus: input.consentStatus || 'granted',
      consentDate: input.consentDate || today,
      consentVersion: input.consentVersion || 'v1.0-DPDP',
      consentGiven: input.consentGiven ?? true,
      completionDate: today,
      certificationDate: today,
      nsqfLevel: Number(input.nsqfLevel) || 4,
      attendanceRate: 92,
      assessmentScore: 82,
      skillRatings: program.assessedSkills.slice(0, 3).map((s) => ({ skill: s, score: 80 })),
    };

    const outcome = input.outcome || 'Employed';
    const placed = ['Employed', 'Self-employed', 'Apprenticeship'].includes(outcome);
    const startingWage = placed ? Number(input.startingWage) || 16500 : 0;

    const employmentRecord = {
      id: `EMP-${seq}`,
      traineeId,
      employerId: input.employerId || null,
      outcome,
      designation: placed
        ? input.designation || (outcome === 'Self-employed' ? 'Founder — own enterprise' : 'Technical Associate')
        : 'Seeking placement',
      startDate: placed ? today : null,
      startingWage,
      currentWage: startingWage,
      monthsInJob: 0,
      verification: 'self_reported',
      lastVerifiedDate: null,
      jobs: placed
        ? [
            {
              employerId: input.employerId || null,
              designation: input.designation || 'Technical Associate',
              startDate: today,
              endDate: null,
              startingWage,
              endingWage: startingWage,
              reasonForLeaving: null,
            },
          ]
        : [],
      wageSnapshots: placed ? [{ atMonths: 0, wage: startingWage }] : [],
      // Business details are placeholders because the current form does not collect
      // them. Do not treat these values as verified. Optional GSTIN/Udyam identifiers
      // belong inside the employees.selfEmployment record.
      selfEmployment: outcome === 'Self-employed'
        ? {
            businessType: 'Not recorded',
            sector: program.sector || 'Not recorded',
            startDate: '',
            location: input.district || 'Pune',
            revenueRange: 'Not recorded',
            businessStatus: 'Operating',
            employees: 0,
            challenges: [],
            gstin: typeof input.gstin === 'string' ? input.gstin.trim().toUpperCase() || undefined : undefined,
            udyamNumber: typeof input.udyamNumber === 'string' ? input.udyamNumber.trim().toUpperCase() || undefined : undefined,
          }
        : null,
      apprenticeship: null,
      nonPlacementReason: ['Unemployed', 'Seeking Employment'].includes(outcome) ? 'Awaiting interviews' : null,
      skillsUsedAtWork: program.assessedSkills.slice(0, 2),
      skillRelevance: 4,
      employerFeedback: 'Enthusiastic and certified skillset.',
    };

    await insertTableRecord('trainees', traineeRecord);
    await insertTableRecord('employees', employmentRecord);

    logActivity(
      'TRAINEE_CREATE',
      'TRAINEE',
      traineeId,
      `Added trainee ${traineeRecord.fullName} (${traineeId})`,
      req.user?.id,
      req.user?.fullName
    );

    res.status(201).json({ success: true, trainee: traineeRecord, employee: employmentRecord });
  } catch (e) {
    console.error('Error creating trainee:', e);
    res.status(500).json({ error: 'Failed to create trainee record' });
  }
});

// PUT /api/trainees/:id (Update)
app.put('/api/trainees/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  try {
    const { traineePatch, employeePatch } = req.body;

    let updatedTrainee = null;
    if (traineePatch) {
      updatedTrainee = await updateTableRecord('trainees', id, traineePatch);
    }

    let updatedEmployee = null;
    if (employeePatch) {
      const employees = await getTableRecords<{ id: string; traineeId: string }>('employees');
      const emp = employees.find((e) => e.traineeId === id);
      if (emp) {
        updatedEmployee = await updateTableRecord('employees', emp.id, employeePatch);
      }
    }

    logActivity('TRAINEE_UPDATE', 'TRAINEE', id, `Updated trainee ${id}`, req.user?.id, req.user?.fullName);

    res.json({ success: true, trainee: updatedTrainee, employee: updatedEmployee });
  } catch (e) {
    console.error('Error updating trainee:', e);
    res.status(500).json({ error: 'Failed to update trainee record' });
  }
});

// DELETE /api/trainees/:id (Delete - admin only)
app.delete('/api/trainees/:id', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  try {
    // Delete trainee
    const ok = await deleteTableRecord('trainees', id);
    if (!ok) {
      res.status(404).json({ error: `Trainee ${id} not found` });
      return;
    }

    // Cascade delete employee record
    const employees = await getTableRecords<{ id: string; traineeId: string }>('employees');
    const emp = employees.find((e) => e.traineeId === id);
    if (emp) {
      await deleteTableRecord('employees', emp.id);
    }

    // Cascade delete follow-up records
    const followups = await getTableRecords<{ id: string; traineeId: string }>('followups');
    const fus = followups.filter((f) => f.traineeId === id);
    for (const f of fus) {
      await deleteTableRecord('followups', f.id);
    }

    logActivity('TRAINEE_DELETE', 'TRAINEE', id, `Deleted trainee ${id} & related records`, req.user?.id, req.user?.fullName);

    res.json({ success: true, message: `Trainee ${id} deleted successfully` });
  } catch (e) {
    console.error('Error deleting trainee:', e);
    res.status(500).json({ error: 'Failed to delete trainee' });
  }
});

// ============================================================================
// Follow-up Actions API
// ============================================================================

// PUT /api/followups/:id/reschedule
app.put('/api/followups/:id/reschedule', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const { days = 7 } = req.body;
    const followups = await listRecords<{ id: string; dueDate: string; traineeId: string }>('followups');
    const followup = followups.find((item) => item.id === id);

    if (!followup) {
      res.status(404).json({ error: 'Follow-up not found' });
      return;
    }

    const next = new Date(followup.dueDate);
    next.setDate(next.getDate() + Number(days));
    const newDate = next.toISOString().slice(0, 10);
    const updated = await updateRecord('followups', id, { dueDate: newDate });

    logActivity('FOLLOWUP_RESCHEDULE', 'FOLLOWUP', id, `Rescheduled to ${newDate}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, record: updated });
  } catch (e) {
    console.error('Failed to reschedule follow-up in MongoDB:', e);
    res.status(500).json({ error: 'Failed to reschedule follow-up' });
  }
});

// POST /api/followups/:id/attempt
app.post('/api/followups/:id/attempt', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const { channel, status, note } = req.body;
    const followups = await listRecords<{ id: string; attempts?: Record<string, unknown>[] }>('followups');
    const followup = followups.find((item) => item.id === id);

    if (!followup) {
      res.status(404).json({ error: 'Follow-up not found' });
      return;
    }

    const today = new Date().toISOString().slice(0, 10);
    const attempt = { date: today, channel, status, note };
    const patch = {
      attempts: [...(followup.attempts || []), attempt],
      lastContact: today,
      contactMethod: channel,
      contactStatus: status,
    };

    const updated = await updateRecord('followups', id, patch);

    logActivity('FOLLOWUP_ATTEMPT', 'FOLLOWUP', id, `${channel}: ${status}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, record: updated });
  } catch (e) {
    console.error('Failed to log follow-up attempt in MongoDB:', e);
    res.status(500).json({ error: 'Failed to log follow-up attempt' });
  }
});

// POST /api/followups/:id/outcome
app.post('/api/followups/:id/outcome', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const { outcome, notes } = req.body;
    const followups = await listRecords<{ id: string; traineeId: string }>('followups');
    const followup = followups.find((item) => item.id === id);

    if (!followup) {
      res.status(404).json({ error: 'Follow-up not found' });
      return;
    }

    const today = new Date().toISOString().slice(0, 10);
    const placed = ['Employed', 'Self-employed', 'Apprenticeship'].includes(outcome);
    const employees = await listRecords<{ id: string; traineeId: string; currentWage: number }>('employees');
    const employee = employees.find((item) => item.traineeId === followup.traineeId);

    if (employee) {
      await updateRecord('employees', employee.id, {
        outcome,
        designation: placed ? 'Recently verified' : 'Seeking placement',
        verification: 'self_reported',
        lastVerifiedDate: today,
      });
    }

    const updated = await updateRecord('followups', id, {
      status: 'Completed',
      lastContact: today,
      employmentConfirmed: placed,
      reportedWage: placed && employee ? employee.currentWage : 0,
      agent: req.user?.fullName || 'District follow-up desk',
      notes: notes || 'Outcome updated.',
    });

    logActivity('FOLLOWUP_COMPLETE', 'FOLLOWUP', id, `Outcome recorded: ${outcome}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, record: updated });
  } catch (e) {
    console.error('Failed to record follow-up outcome in MongoDB:', e);
    res.status(500).json({ error: 'Failed to record follow-up outcome' });
  }
});

// POST /api/followups (Create new immutable follow-up log)
app.post('/api/followups', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const {
      traineeId,
      outcome,
      reportedWage,
      employerName,
      verification,
      feedback,
      notes,
      channel = 'WhatsApp',
      milestone = '30-day',
      jobSatisfaction = 4,
      skillRelevanceRating = 4,
    } = req.body;

    if (!traineeId) {
      res.status(400).json({ error: 'traineeId is required.' });
      return;
    }

    const trainees = await listRecords<Record<string, unknown>>('trainees');
    const trainee = trainees.find((t) => t.id === traineeId);

    if (!trainee) {
      res.status(404).json({ error: `Trainee ${traineeId} not found` });
      return;
    }

    const today = new Date().toISOString().slice(0, 10);
    const fuId = `FU-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const placed = ['Employed', 'Self-employed', 'Apprenticeship'].includes(outcome || 'Employed');
    const wage = Number(reportedWage) || 0;

    const followupRecord = {
      id: fuId,
      traineeId,
      status: 'Completed',
      dueDate: today,
      milestone: milestone || 'Follow-up',
      lastContact: today,
      contactMethod: channel || 'WhatsApp',
      contactStatus: 'Contacted',
      priority: 'Medium',
      employmentConfirmed: placed,
      reportedWage: placed ? wage : 0,
      jobSatisfaction: Number(jobSatisfaction) || 4,
      skillRelevanceRating: Number(skillRelevanceRating) || 4,
      agent: req.user?.fullName || 'District Follow-up Bot',
      notes: notes || feedback || `Recorded via ${channel} follow-up. Outcome: ${outcome}`,
      attempts: [
        {
          date: today,
          channel: channel || 'WhatsApp',
          status: 'Contacted',
          note: notes || 'Direct candidate response',
        },
      ],
    };

    await insertRecord('followups', followupRecord);

    const employees = await listRecords<Record<string, unknown>>('employees');
    const emp = employees.find((e) => e.traineeId === traineeId);

    if (emp) {
      const patch: Record<string, unknown> = {
        outcome: outcome || emp.outcome,
        verification: verification || (channel === 'WhatsApp' ? 'self_reported' : 'document_verified'),
        lastVerifiedDate: today,
      };

      if (placed && wage > 0) {
        patch.currentWage = wage;
      }

      if (employerName) {
        patch.designation = `${emp.designation || 'Specialist'} at ${employerName}`;
      }

      await updateRecord('employees', String(emp.id), patch);
    }

    logActivity(
      'FOLLOWUP_SUBMIT',
      'FOLLOWUP',
      fuId,
      `Submitted periodic follow-up for ${trainee.fullName} (${traineeId}) via ${channel}: ${outcome}`,
      req.user?.id,
      req.user?.fullName
    );

    res.status(201).json({ success: true, followup: followupRecord });
  } catch (e) {
    console.error('Error recording follow-up:', e);
    res.status(500).json({ error: 'Failed to record follow-up' });
  }
});

// GET /api/followups/trainee/:traineeId
app.get('/api/followups/trainee/:traineeId', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { traineeId } = req.params;
    const allFollowups = await listRecords<Record<string, unknown>>('followups');

    const followups = allFollowups
      .filter((f) => f.traineeId === traineeId)
      .sort((a, b) =>
        String(b.lastContact || '').localeCompare(String(a.lastContact || ''))
      );

    res.json({ followups });
  } catch (e) {
    console.error('Failed to fetch follow-up history from MongoDB:', e);
    res.status(500).json({ error: 'Failed to fetch follow-ups for trainee' });
  }
});

// ============================================================================
// Flag for Follow-Up & Simulated Reminder Log API
// ============================================================================

// POST /api/reminders/simulate
app.post('/api/reminders/simulate', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { traineeId, traineeName, phone, channel = 'WhatsApp', milestone, notes } = req.body;
    if (!traineeId || !traineeName) {
      res.status(400).json({ error: 'traineeId and traineeName are required.' });
      return;
    }

    const log = await insertReminderLog({
      traineeId,
      traineeName,
      phone: phone || '',
      channel: channel as 'WhatsApp' | 'SMS' | 'Email' | 'IVR',
      status: 'delivered_simulated',
      milestone: milestone || '30-day',
      initiatedBy: req.user?.fullName || 'District Follow-up Officer',
      notes: notes || `Simulated reminder ping sent via ${channel} gateway.`,
    });

    logActivity(
      'REMINDER_SENT',
      'REMINDER',
      log.id,
      `Dispatched simulated ${channel} reminder to ${traineeName} (${traineeId})`,
      req.user?.id,
      req.user?.fullName
    );

    res.status(201).json({
      success: true,
      log,
      message: `Demo reminder recorded successfully. In production, this would trigger an SMS / WhatsApp message via government gateway.`,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to log reminder' });
  }
});

// POST /api/reminders/bulk-simulate
app.post('/api/reminders/bulk-simulate', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { trainees, channel = 'WhatsApp', milestone = 'Overdue' } = req.body;
    if (!Array.isArray(trainees) || trainees.length === 0) {
      res.status(400).json({ error: 'trainees array is required.' });
      return;
    }

    const created: ReminderLog[] = [];
    for (const t of trainees) {
      const log = await insertReminderLog({
        traineeId: t.id || t.traineeId,
        traineeName: t.fullName || t.traineeName || 'Trainee',
        phone: t.phone || '',
        channel: channel as 'WhatsApp' | 'SMS' | 'Email' | 'IVR',
        status: 'delivered_simulated',
        milestone: milestone,
        initiatedBy: req.user?.fullName || 'District Follow-up Officer',
        notes: `Bulk automated reminder dispatched via ${channel}.`,
      });
      created.push(log);
    }

    logActivity(
      'BULK_REMINDER_SENT',
      'REMINDER',
      'BULK',
      `Dispatched bulk ${channel} reminders to ${created.length} trainees`,
      req.user?.id,
      req.user?.fullName
    );

    res.status(201).json({
      success: true,
      count: created.length,
      logs: created,
      message: `Bulk reminders recorded for ${created.length} trainees. (Simulation)`,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to send bulk reminders' });
  }
});

// GET /api/reminders
app.get('/api/reminders', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { traineeId, limit = '50' } = req.query;
    if (traineeId && typeof traineeId === 'string') {
      const logs = await getReminderLogsByTrainee(traineeId);
      res.json({ logs });
      return;
    }
    const logs = await getReminderLogs(Math.min(200, parseInt(String(limit), 10) || 50));
    res.json({ logs });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch reminder logs' });
  }
});

// ============================================================================
// Courses & Providers Management API
// ============================================================================

// GET /api/courses
app.get('/api/courses', requireAuth, async (_req: AuthenticatedRequest, res: Response) => {
  try {
    const courses = await listRecords('trainingPrograms');
    res.json({ courses });
  } catch (e) {
    console.error('Failed to load courses from MongoDB:', e);
    res.status(500).json({ error: 'Failed to load courses' });
  }
});

// POST /api/courses
app.post('/api/courses', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const input = req.body;
    if (!input.courseName || !input.sector) {
      res.status(400).json({ error: 'courseName and sector are required.' });
      return;
    }
    const id = input.id || `PRG-MH-${Date.now().toString().slice(-4)}`;
    const course = {
      id,
      courseName: input.courseName,
      sector: input.sector,
      nsqfLevel: Number(input.nsqfLevel) || 4,
      durationHours: Number(input.durationHours) || 300,
      providerCount: Number(input.providerCount) || 1,
      enrolled: Number(input.enrolled) || 0,
      completed: Number(input.completed) || 0,
      certified: Number(input.certified) || 0,
      placed: Number(input.placed) || 0,
      completionRate: Number(input.completionRate) || 85,
      employmentRate: Number(input.employmentRate) || 75,
      averageStartingWage: Number(input.averageStartingWage) || 16000,
      averageWage12M: Number(input.averageWage12M) || 20000,
      retentionRate6M: Number(input.retentionRate6M) || 80,
      topEmployers: input.topEmployers || ['Tata Motors', 'Mahindra', 'Bajaj Auto'],
      isActive: input.isActive ?? true,
      assessedSkills: input.assessedSkills || ['Core Trade Skills', 'Workplace Safety'],
    };
    await insertRecord('trainingPrograms', course);
    logActivity('COURSE_CREATE', 'COURSE', id, `Created course ${course.courseName}`, req.user?.id, req.user?.fullName);
    res.status(201).json({ success: true, course });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create course' });
  }
});

// PUT /api/courses/:id
app.put('/api/courses/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const updated = await updateRecord('trainingPrograms', id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Course not found' });
      return;
    }

    logActivity('COURSE_UPDATE', 'COURSE', id, `Updated course ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, course: updated });
  } catch (e) {
    console.error('Failed to update course in MongoDB:', e);
    res.status(500).json({ error: 'Failed to update course' });
  }
});

// DELETE /api/courses/:id
app.delete('/api/courses/:id', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const deleted = await deleteRecord('trainingPrograms', id);
    if (!deleted) {
      res.status(404).json({ error: 'Course not found' });
      return;
    }

    logActivity('COURSE_DELETE', 'COURSE', id, `Deleted course ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, message: `Course ${id} deleted` });
  } catch (e) {
    console.error('Failed to delete course from MongoDB:', e);
    res.status(500).json({ error: 'Failed to delete course' });
  }
});

// GET /api/providers
app.get('/api/providers', requireAuth, async (_req: AuthenticatedRequest, res: Response) => {
  try {
    const providers = await listRecords('providers');
    res.json({ providers });
  } catch (e) {
    console.error('Failed to load providers from MongoDB:', e);
    res.status(500).json({ error: 'Failed to load providers' });
  }
});
// POST /api/providers
app.post('/api/providers', requireAuth, async(req: AuthenticatedRequest, res: Response) => {
  try {
    const input = req.body;
    if (!input.name || !input.type) {
      res.status(400).json({ error: 'name and type are required.' });
      return;
    }
    const id = input.id || `VTP-MH-${Date.now().toString().slice(-4)}`;
    const provider = {
      id,
      code: input.code || `MH-${id.slice(-4)}`,
      name: input.name,
      type: input.type,
      districtsCovered: input.districtsCovered || ['Pune'],
      centres: Number(input.centres) || 1,
      totalTrainees: Number(input.totalTrainees) || 0,
      certified: Number(input.certified) || 0,
      completionRate: Number(input.completionRate) || 85,
      employmentRate: Number(input.employmentRate) || 75,
      retentionRate6M: Number(input.retentionRate6M) || 80,
      averageStartingWage: Number(input.averageStartingWage) || 16000,
      wageGrowth12M: Number(input.wageGrowth12M) || 15,
      outcomeVerificationScore: Number(input.outcomeVerificationScore) || 90,
      performanceTier: input.performanceTier || 'A',
      isActive: input.isActive ?? true,
    };
    await insertRecord('providers', provider);
    logActivity('PROVIDER_CREATE', 'PROVIDER', id, `Created provider ${provider.name}`, req.user?.id, req.user?.fullName);
    res.status(201).json({ success: true, provider });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create provider' });
  }
});

// PUT /api/providers/:id
app.put('/api/providers/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const updated = await updateRecord('providers', id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Provider not found' });
      return;
    }

    logActivity('PROVIDER_UPDATE', 'PROVIDER', id, `Updated provider ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, provider: updated });
  } catch (e) {
    console.error('Failed to update provider in MongoDB:', e);
    res.status(500).json({ error: 'Failed to update provider' });
  }
});

// DELETE /api/providers/:id
app.delete('/api/providers/:id', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;

  try {
    const deleted = await deleteRecord('providers', id);
    if (!deleted) {
      res.status(404).json({ error: 'Provider not found' });
      return;
    }

    logActivity('PROVIDER_DELETE', 'PROVIDER', id, `Deleted provider ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, message: `Provider ${id} deleted` });
  } catch (e) {
    console.error('Failed to delete provider from MongoDB:', e);
    res.status(500).json({ error: 'Failed to delete provider' });
  }
});

// ============================================================================
// Bulk Trainee Import & Simulated Government Integrations API
// ============================================================================

// POST /api/trainees/bulk
app.post('/api/trainees/bulk', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { trainees } = req.body;
    if (!Array.isArray(trainees) || trainees.length === 0) {
      res.status(400).json({ error: 'trainees array is required.' });
      return;
    }

    const currentCount = (await getTableRecords('trainees')).length;
    const today = new Date().toISOString().slice(0, 10);
    const insertedIds: string[] = [];

    for (let i = 0; i < trainees.length; i++) {
      const item = trainees[i];
      if (!item.fullName) continue;

      const seq = String(20000 + currentCount + i + 1).padStart(5, '0');
      const traineeId = item.id || `ST-2026-MH-${seq}`;

      const traineeRecord = {
        id: traineeId,
        fullName: String(item.fullName).trim(),
        gender: item.gender || 'Female',
        age: Number(item.age) || 22,
        phone: item.phone || `+91 ${Math.floor(9000000000 + Math.random() * 999999999)}`,
        email: item.email || `${String(item.fullName).toLowerCase().replace(/[^a-z]/g, '')}.${seq.slice(-3)}@maha-skills.org`,
        district: item.district || 'Pune',
        division: item.division || 'Pune',
        category: item.category || 'General',
        education: item.education || '12th Pass / ITI',
        trainingYear: item.trainingYear || '2024-25',
        programId: item.programId || 'PRG-AUTO-001',
        providerId: item.providerId || 'VTP-PUN-001',
        batchId: `B-${seq.slice(-3)}`,
        enrolmentDate: item.enrolmentDate || today,
        consentStatus: 'granted',
        consentDate: today,
        consentVersion: 'v1.0-DPDP',
        consentGiven: true,
        completionDate: today,
        certificationDate: today,
        nsqfLevel: Number(item.nsqfLevel) || 4,
        attendanceRate: Number(item.attendanceRate) || 90,
        assessmentScore: Number(item.assessmentScore) || 80,
        skillRatings: [{ skill: 'Trade skills', score: 80 }],
      };

      const outcome = item.outcome || 'Employed';
      const placed = ['Employed', 'Self-employed', 'Apprenticeship'].includes(outcome);
      const startingWage = placed ? Number(item.startingWage) || 16500 : 0;

      const employmentRecord = {
        id: `EMP-${seq}`,
        traineeId,
        employerId: item.employerId || null,
        outcome,
        designation: placed ? item.designation || 'Technical Associate' : 'Seeking placement',
        startDate: placed ? today : null,
        startingWage,
        currentWage: startingWage,
        monthsInJob: 0,
        verification: 'self_reported',
        lastVerifiedDate: null,
        jobs: [],
        wageSnapshots: placed ? [{ atMonths: 0, wage: startingWage }] : [],
        selfEmployment: null,
        apprenticeship: null,
        nonPlacementReason: null,
        skillsUsedAtWork: [],
        skillRelevance: 4,
        employerFeedback: 'Enrolled via bulk administrative upload.',
      };

      await insertTableRecord('trainees', traineeRecord);
      await insertTableRecord('employees', employmentRecord);
      insertedIds.push(traineeId);
    }

    logActivity(
      'TRAINEE_BULK_IMPORT',
      'TRAINEE',
      'BULK',
      `Bulk imported ${insertedIds.length} trainees`,
      req.user?.id,
      req.user?.fullName
    );

    res.status(201).json({ success: true, count: insertedIds.length, insertedIds });
  } catch (e) {
    console.error('Error bulk importing trainees:', e);
    res.status(500).json({ error: 'Failed to bulk import trainees' });
  }
});

// Mock Integrations Endpoints (clearly labeled simulated demo)
app.post('/api/integrations/mock-sms', async (req: Request, res: Response) => {
  const { phone, message } = req.body;
  res.json({
    success: true,
    simulated: true,
    gateway: 'MahaGovt CDAC National SMS Gateway v2.4 (Simulated)',
    messageId: `SMS-MH-${Date.now().toString().slice(-6)}`,
    recipient: phone || '+91 98200 12345',
    charsCount: String(message || '').length,
    status: 'DELIVRD_SIMULATED',
    latencyMs: Math.floor(80 + Math.random() * 120),
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/integrations/mock-epfo', async (req: Request, res: Response) => {
  const { uan, traineeId } = req.body;
  const companies = [
    { name: 'Tata AutoComp Systems Ltd', code: 'MH/PUN/0049281/000' },
    { name: 'Bharat Forge Ltd', code: 'MH/PUN/0018274/000' },
    { name: 'L&T Infotech Mahape', code: 'MH/THN/0091823/000' },
    { name: 'Bajaj Finserv Operations', code: 'MH/PUN/0066291/000' },
  ];
  const choice = companies[Math.floor(Math.random() * companies.length)];
  res.json({
    verified: true,
    simulated: true,
    uan: uan || '101928374652',
    traineeId: traineeId || 'ST-2024-MH-20001',
    agency: 'Ministry of Labour & Employment — EPFO Unified Portal (Simulated Demo)',
    establishmentName: choice.name,
    establishmentCode: choice.code,
    lastContributionMonth: 'February 2026',
    wageVerified: true,
    serviceTenureMonths: 8,
    status: 'ACTIVE_CONTRIBUTING_MEMBER',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/integrations/mock-digilocker', async (req: Request, res: Response) => {
  const { aadhaarLast4, traineeName } = req.body;
  res.json({
    verified: true,
    simulated: true,
    agency: 'DigiLocker / UIDAI National e-Governance Division (Simulated Demo)',
    docType: 'AADHAAR_KYC',
    status: 'AUTHENTICATED_VERIFIED',
    issuedTo: traineeName || 'Candidate',
    aadhaarMasked: `XXXX-XXXX-${aadhaarLast4 || '4921'}`,
    docUri: `in.gov.uidai-aadhaar-MH-${Date.now().toString().slice(-6)}`,
    verificationHash: `SHA256-${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================================
// Admin Management API
// ============================================================================

// GET /api/admin/users
app.get('/api/admin/users', requireAdmin, async (_req: AuthenticatedRequest, res: Response) => {
  try {
    const users = await getUsersCollection().find({}, { projection: { _id: 0, passwordHash: 0 } }).sort({ createdAt: -1 }).toArray();
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// PUT /api/admin/users/:id/role
app.put('/api/admin/users/:id/role', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (role !== 'admin' && role !== 'user') {
      res.status(400).json({ error: 'Role must be either admin or user' });
      return;
    }

    if (id === req.user?.id && role === 'user') {
      res.status(400).json({ error: 'Cannot demote your own administrator account' });
      return;
    }

    const now = new Date().toISOString();
    const result = await getUsersCollection().updateOne({ id }, { $set: { role, updatedAt: now } });
    if (result.matchedCount === 0) { res.status(404).json({ error: 'User not found' }); return; }

    logActivity('USER_ROLE_CHANGE', 'USER', id, `Role updated to ${role}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, message: `User role updated to ${role}` });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    if (id === req.user?.id) {
      res.status(400).json({ error: 'Cannot delete your own account while logged in' });
      return;
    }

    const result = await getUsersCollection().deleteOne({ id });
    if (result.deletedCount === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    logActivity('USER_DELETE', 'USER', id, `Deleted user account ${id}`, req.user?.id, req.user?.fullName);
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// GET /api/admin/logs
app.get('/api/admin/logs', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const limit = Math.min(100, parseInt(String(req.query.limit || '50'), 10));
    const logs = await getLogs(limit);
    res.json({ logs });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// POST /api/admin/reset
app.post('/api/admin/reset', requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    await seedDatabase(true);
    logActivity('DATABASE_RESET', 'SYSTEM', 'SYSTEM', 'MongoDB operational data reset from public/data seed files', req.user?.id, req.user?.fullName);
    res.json({ success: true, message: 'MongoDB operational data reset from public/data seed files. User accounts and logs were preserved.' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to reset database' });
  }
});

// ============================================================================
// Dynamic Report Download API
// ============================================================================

app.get('/api/reports/:id/download', requireAuth, async (_req: AuthenticatedRequest, res: Response) => {
  const { id } = _req.params;
  try {
    const trainees = await getTableRecords<Record<string, unknown>>('trainees');
    const employees = await getTableRecords<Record<string, unknown>>('employees');
    const empByTrainee = new Map(employees.map((e) => [String(e.traineeId), e]));

    let filename = `Maharashtra_SkillTrack_${id}_Report_${new Date().toISOString().slice(0, 10)}.csv`;
    let csvContent = '';

    if (id === 'outcomes') {
      filename = `Maharashtra_Employment_Outcomes_Report_${new Date().toISOString().slice(0, 10)}.csv`;
      csvContent = 'Trainee ID,Full Name,District,Program,Outcome,Designation,Starting Wage,Current Wage,Verification\n';
      for (const t of trainees) {
        const emp = empByTrainee.get(String(t.id));
        csvContent += `"${t.id}","${t.fullName}","${t.district}","${t.programId}","${emp?.outcome || 'Unknown'}","${emp?.designation || '—'}",${emp?.startingWage || 0},${emp?.currentWage || 0},"${emp?.verification || 'unverified'}"\n`;
      }
    } else if (id === 'districts') {
      filename = `Maharashtra_District_Performance_Report_${new Date().toISOString().slice(0, 10)}.csv`;
      const districtCounts: Record<string, { total: number; employed: number; wages: number[] }> = {};
      for (const t of trainees) {
        const d = String(t.district || 'Unknown');
        if (!districtCounts[d]) districtCounts[d] = { total: 0, employed: 0, wages: [] };
        districtCounts[d].total++;
        const emp = empByTrainee.get(String(t.id));
        if (emp && ['Employed', 'Self-employed', 'Apprenticeship'].includes(String(emp.outcome))) {
          districtCounts[d].employed++;
          if (Number(emp.currentWage) > 0) districtCounts[d].wages.push(Number(emp.currentWage));
        }
      }
      csvContent = 'District,Total Trainees,Employed Count,Employment Rate (%),Average Wage (INR)\n';
      for (const [d, stat] of Object.entries(districtCounts)) {
        const empRate = stat.total > 0 ? ((stat.employed / stat.total) * 100).toFixed(1) : '0';
        const avgWage = stat.wages.length > 0 ? Math.round(stat.wages.reduce((a, b) => a + b, 0) / stat.wages.length) : 0;
        csvContent += `"${d}",${stat.total},${stat.employed},${empRate},${avgWage}\n`;
      }
    } else {
      csvContent = 'Trainee ID,Full Name,Gender,Age,District,Category,Program,Attendance,Assessment Score\n';
      for (const t of trainees.slice(0, 500)) {
        csvContent += `"${t.id}","${t.fullName}","${t.gender}",${t.age},"${t.district}","${t.category}","${t.programId}",${t.attendanceRate},${t.assessmentScore}\n`;
      }
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  } catch (e) {
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

async function seedDefaultUsers() {
  const usersCol = getUsersCollection();
  const defaultAdmin = await usersCol.findOne({ email: 'admin@skilltrack.gov.in' });
  if (!defaultAdmin) {
    await usersCol.insertOne({
      id: 'USR-ADMIN-001',
      fullName: 'State Skill Administrator',
      email: 'admin@skilltrack.gov.in',
      passwordHash: hashPassword('Admin@12345'),
      role: 'admin',
      district: 'Mumbai City',
      phone: '+91 22 2202 5221',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    console.log('✓ Seeded default admin account: admin@skilltrack.gov.in / Admin@12345');
  }

  const defaultCitizen = await usersCol.findOne({ email: 'citizen@skilltrack.gov.in' });
  if (!defaultCitizen) {
    await usersCol.insertOne({
      id: 'USR-CITIZEN-001',
      fullName: 'Ramesh Narayan Deshmukh',
      email: 'citizen@skilltrack.gov.in',
      passwordHash: hashPassword('Citizen@12345'),
      role: 'user',
      district: 'Pune',
      phone: '+91 98220 12345',
      traineeId: 'TR-1001',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    console.log('✓ Seeded default citizen account: citizen@skilltrack.gov.in / Citizen@12345');
  }
}

// Start Express Server
async function startServer() {
  const uri = process.env.MONGODB_URI;

  try {
    if (!uri) throw new Error('MONGODB_URI is missing from .env');

    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 4000,
    });

    console.log(
      `✓ MongoDB connected to database: ${mongoose.connection.name}`
    );

    const database = mongoose.connection.db;

    if (database) {
      await getUsersCollection().createIndex(
        { email: 1 },
        { unique: true }
      );

      for (const table of [
        'trainees',
        'employees',
        'trainingPrograms',
        'providers',
        'employers',
        'skills',
        'followups',
        'activity_logs',
        'reminder_logs',
      ]) {
        await database.collection(table).createIndex(
          { id: 1 },
          { unique: true }
        );
      }
    }

    await seedDatabase(false);
  } catch (error: any) {
    console.warn(
      `⚠ Notice: Running in resilient datastore mode (${error?.message || 'offline'}).`
    );

    await seedDatabase(true);
  }

  await seedDefaultUsers();
}

if (!process.env.VERCEL) {
  startServer()
    .then(() => {
      app.listen(PORT, '0.0.0.0', () => {
        console.log(`✓ SkillTrack API server running on http://localhost:${PORT}`);
        console.log(`  Demo Admin:   admin@skilltrack.gov.in / Admin@12345`);
        console.log(`  Demo Citizen: citizen@skilltrack.gov.in / Citizen@12345`);
      });
    })
    .catch((error) => {
      console.error('Failed to start server:', error.message);
      process.exit(1);
    });
}

export { startServer };
export default app;