require('dotenv').config({ quiet: true });
const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { connectToMongo } = require('./mongodb');
const { createClerkClient } = require('@clerk/clerk-sdk-node');
const logger = require('./logger');

// ============================================================================
// CONSTANTS
// ============================================================================
const TIMEZONE = 'Asia/Kolkata'; // IST (UTC+5:30) — All users are in India
const IST_OFFSET = '+05:30';

const config = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET || 'your-secret-key',
  JWT_EXPIRY: '7d',
  AWS: {
    REGION: process.env.AWS_REGION || 'us-east-1',
    ACCESS_KEY: process.env.AWS_ACCESS_KEY,
    SECRET_KEY: process.env.AWS_SECRET_KEY,
    COLLECTION_ID: process.env.COLLECTION_ID || 'attendance-collection',
  },
  FACE_MATCH_THRESHOLD: 90,
  FACE_VERIFICATION_THRESHOLD: 75,
  FILE_SIZE_LIMIT: 5 * 1024 * 1024,
  CORS: {
    origin: process.env.CORS_ORIGIN || true,
    credentials: true,
  },
  COLLECTIONS: {
    STAFF: 'staff',
    WORKERS: 'workers',
    ATTENDANCE: 'attendance',
    AUDIT: 'audit_logs',
  },
};

// ============================================================================
// INITIALIZE
// ============================================================================
const app = express();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.FILE_SIZE_LIMIT },
  fileFilter: (_req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (allowedMimes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type. Only JPEG and PNG allowed.'));
  },
});

const rekognition = new AWS.Rekognition({
  accessKeyId: config.AWS.ACCESS_KEY,
  secretAccessKey: config.AWS.SECRET_KEY,
  region: config.AWS.REGION,
});

const clerkClient = createClerkClient({
  secretKey: process.env.CLERK_SECRET_KEY,
});

app.use(cors(config.CORS));
app.use(express.json());

// Request Logger
app.use((req, _res, next) => {
  const sanitizedBody = { ...req.body };
  if (sanitizedBody.password) sanitizedBody.password = '***REDACTED***';
  logger.info(`[${req.method}] ${req.path}`, { body: sanitizedBody });
  next();
});

// ============================================================================
// IST TIMESTAMP HELPERS — Server always uses Indian Standard Time
// ============================================================================

/**
 * Get current IST timestamp with all needed formats.
 * No frontend input needed — server converts UTC → IST.
 */
function getISTTimestamp() {
  const now = new Date();

  const localDate = now.toLocaleDateString('en-CA', {
    timeZone: TIMEZONE,
  }); // "2025-01-15"

  const localTime = now.toLocaleTimeString('en-US', {
    timeZone: TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  }); // "08:00:00 PM"

  return {
    utc: now,
    iso: now.toISOString(),
    localDate,
    localTime,
    timezone: TIMEZONE,
  };
}

/**
 * Get start of today in IST → returned as UTC Date for MongoDB queries.
 * IST midnight (00:00) = UTC 18:30 previous day.
 */
function getISTStartOfDay(date = new Date()) {
  const istDateStr = date.toLocaleDateString('en-CA', {
    timeZone: TIMEZONE,
  });
  return new Date(`${istDateStr}T00:00:00${IST_OFFSET}`);
}

/**
 * Get end of today in IST → returned as UTC Date for MongoDB queries.
 * IST 23:59:59.999 = UTC 18:29:59.999 same day.
 */
function getISTEndOfDay(date = new Date()) {
  const istDateStr = date.toLocaleDateString('en-CA', {
    timeZone: TIMEZONE,
  });
  return new Date(`${istDateStr}T23:59:59.999${IST_OFFSET}`);
}

// ============================================================================
// GENERAL HELPERS
// ============================================================================
function validateRequiredFields(data, fields) {
  const missing = fields.filter((field) => !data[field]);
  if (missing.length > 0) throw new Error(`Missing: ${missing.join(', ')}`);
}

function sendError(res, statusCode, message, error = null) {
  logger.error(message, error);
  return res.status(statusCode).json({
    success: false,
    message,
    ...(config.NODE_ENV === 'development' &&
      error && { details: error.message }),
  });
}

function sendSuccess(res, data, statusCode = 200) {
  return res.status(statusCode).json({ success: true, ...data });
}

function generateJWT(payload) {
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRY });
}

// ============================================================================
// AUDIT LOGGER
// ============================================================================
async function auditLog(action, performedBy, targetUser, details, req) {
  try {
    const db = await connectToMongo();
    const ist = getISTTimestamp();
    await db.collection(config.COLLECTIONS.AUDIT).insertOne({
      action,
      performedBy,
      targetUser,
      details,
      ipAddress: req?.ip || req?.connection?.remoteAddress || null,
      userAgent: req?.headers?.['user-agent'] || null,
      timestamps: {
        utc: ist.utc,
        localDate: ist.localDate,
        localTime: ist.localTime,
        timezone: ist.timezone,
      },
      createdAt: ist.utc,
    });
  } catch (error) {
    logger.error('Audit log failed', error);
  }
}

// ============================================================================
// AWS HELPERS
// ============================================================================
async function searchFaceByImage(imageBuffer) {
  try {
    const params = {
      CollectionId: config.AWS.COLLECTION_ID,
      Image: { Bytes: imageBuffer },
      MaxFaces: 1,
      FaceMatchThreshold: config.FACE_MATCH_THRESHOLD,
    };
    return await rekognition.searchFacesByImage(params).promise();
  } catch (error) {
    if (
      error.code === 'InvalidParameterException' &&
      error.message.includes('no faces')
    ) {
      return { FaceMatches: [] };
    }
    throw error;
  }
}

async function indexFaceInCollection(imageBuffer, userId) {
  const params = {
    CollectionId: config.AWS.COLLECTION_ID,
    Image: { Bytes: imageBuffer },
    ExternalImageId: userId,
    DetectionAttributes: ['ALL'],
    MaxFaces: 1,
    QualityFilter: 'AUTO',
  };
  return await rekognition.indexFaces(params).promise();
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

/**
 * Auth Middleware - ONLY for staff & admin
 * Reads from 'staff' collection (not 'workers')
 */
async function authMiddleware(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return sendError(res, 401, 'Authentication token required.');

    const decoded = jwt.verify(token, config.JWT_SECRET);
    const db = await connectToMongo();

    const staffUser = await db
      .collection(config.COLLECTIONS.STAFF)
      .findOne({ userId: decoded.userId });

    if (!staffUser) return sendError(res, 404, 'Staff account not found.');
    if (!staffUser.isActive) return sendError(res, 403, 'Account deactivated.');
    if (staffUser.isLocked) return sendError(res, 403, 'Account locked.');

    req.user = staffUser;
    next();
  } catch (error) {
    return sendError(res, 401, 'Invalid or expired token.', error);
  }
}

function checkRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return sendError(res, 401, 'Auth required.');
    if (!allowedRoles.includes(req.user.role)) {
      return sendError(res, 403, 'Access denied. Insufficient permissions.');
    }
    next();
  };
}

// ============================================================================
// ROUTE: POST /api/signin (Staff & Admin ONLY)
// ============================================================================
app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    validateRequiredFields({ email, password }, ['email', 'password']);

    const users = await clerkClient.users.getUserList({
      emailAddress: [email],
    });

    if (!users || users.length === 0) {
      await auditLog(
        'SIGNIN_FAILED',
        null,
        null,
        { email, reason: 'User not found in Clerk' },
        req,
      );
      return sendError(res, 401, 'Invalid credentials.');
    }

    const clerkUser = users[0];

    let role = clerkUser.privateMetadata?.role;
    if (!role) {
      role = 'staff';
      try {
        await clerkClient.users.updateUser(clerkUser.id, {
          privateMetadata: {
            ...clerkUser.privateMetadata,
            role: 'staff',
          },
        });
        logger.info(`Auto-assigned 'staff' role to ${email} in Clerk`);
      } catch (metaErr) {
        logger.warn(
          `Failed to update Clerk metadata for ${email}:`,
          metaErr.message,
        );
      }
    }

    if (!['admin', 'staff'].includes(role)) {
      await auditLog(
        'SIGNIN_DENIED',
        null,
        null,
        {
          email,
          reason: `Role '${role || 'none'}' is not allowed to sign in`,
        },
        req,
      );
      return sendError(
        res,
        403,
        'Access Denied. Only admin and staff can sign in.',
      );
    }

    if (clerkUser.locked) {
      await auditLog(
        'SIGNIN_FAILED',
        null,
        null,
        { email, reason: 'Account locked in Clerk' },
        req,
      );
      return sendError(res, 403, 'Account locked.');
    }

    const { verified } = await clerkClient.users.verifyPassword({
      userId: clerkUser.id,
      password,
    });

    if (!verified) {
      await auditLog(
        'SIGNIN_FAILED',
        null,
        null,
        { email, reason: 'Wrong password' },
        req,
      );
      return sendError(res, 401, 'Invalid credentials.');
    }

    const userId =
      clerkUser.username ?? `${clerkUser.firstName}-${clerkUser.lastName}`;

    const db = await connectToMongo();
    const ist = getISTTimestamp();

    await db.collection(config.COLLECTIONS.STAFF).updateOne(
      { userId: userId },
      {
        $setOnInsert: {
          isActive: true,
          isLocked: false,
          createdAt: ist.utc,
          createdBy: 'clerk_dashboard',
          email: email,
        },
        $set: {
          role: role,
          firstName: clerkUser.firstName,
          lastName: clerkUser.lastName,
          updatedAt: ist.utc,
          lastSignInAt: ist.utc,
          lastSignInLocal: ist.localTime,
        },
      },
      { upsert: true },
    );

    const dbUser = await db
      .collection(config.COLLECTIONS.STAFF)
      .findOne({ userId: userId });

    if (!dbUser) {
      return sendError(res, 500, 'Failed to create staff record.');
    }

    const token = generateJWT({
      userId: dbUser.userId,
      email: email,
      role: dbUser.role,
    });

    await auditLog(
      'SIGNIN_SUCCESS',
      userId,
      null,
      { email, role: dbUser.role },
      req,
    );

    logger.info(`Staff signed in: ${email} (${role}) at ${ist.localTime} IST`);

    return sendSuccess(res, {
      message: 'Login successful',
      token,
      user: {
        userId: dbUser.userId,
        email: email,
        firstName: clerkUser.firstName,
        lastName: clerkUser.lastName,
        role: dbUser.role,
      },
    });
  } catch (error) {
    await auditLog('SIGNIN_ERROR', null, null, { error: error.message }, req);
    return sendError(res, 401, 'Authentication failed', error);
  }
});

// ============================================================================
// ROUTE: POST /api/enroll (Admin & Staff - Enroll workers)
// ============================================================================
app.post(
  '/api/enroll',
  authMiddleware,
  checkRole('admin', 'staff'),
  upload.single('image'),
  async (req, res) => {
    try {
      const { workerId, firstName, lastName, age, designation, location } =
        req.body;
      const imageBuffer = req.file?.buffer;

      if (!workerId || !imageBuffer) {
        return sendError(res, 400, 'Worker ID and face image are required.');
      }

      if (!firstName || !lastName) {
        return sendError(res, 400, 'First name and last name are required.');
      }

      const db = await connectToMongo();

      const searchResult = await searchFaceByImage(imageBuffer);

      if (searchResult.FaceMatches && searchResult.FaceMatches.length > 0) {
        const existingId = searchResult.FaceMatches[0].Face.ExternalImageId;

        await auditLog(
          'ENROLL_FAILED',
          req.user.userId,
          workerId,
          { reason: 'Face already registered', existingUserId: existingId },
          req,
        );

        return sendError(
          res,
          409,
          `This face is already registered to worker ID: ${existingId}.`,
        );
      }

      const existingWorker = await db
        .collection(config.COLLECTIONS.WORKERS)
        .findOne({ workerId: workerId });

      if (existingWorker && existingWorker.awsFaceId) {
        await auditLog(
          'ENROLL_FAILED',
          req.user.userId,
          workerId,
          { reason: 'Worker ID already enrolled' },
          req,
        );
        return sendError(res, 409, `Worker ${workerId} is already enrolled.`);
      }

      const indexResult = await indexFaceInCollection(imageBuffer, workerId);

      if (!indexResult.FaceRecords || indexResult.FaceRecords.length === 0) {
        await auditLog(
          'ENROLL_FAILED',
          req.user.userId,
          workerId,
          { reason: 'No face detected in image' },
          req,
        );
        return sendError(res, 400, 'No face detected in image.');
      }

      const faceRecord = indexResult.FaceRecords[0].Face;
      const ist = getISTTimestamp();

      await db.collection(config.COLLECTIONS.WORKERS).updateOne(
        { workerId: workerId },
        {
          $set: {
            firstName,
            lastName,
            awsFaceId: faceRecord.FaceId,
            enrollmentConfidence: faceRecord.Confidence,
            enrolledAt: ist.utc,
            enrolledAtLocal: `${ist.localDate} ${ist.localTime}`,
            enrolledBy: req.user.userId,
            enrolledByRole: req.user.role,
            ...(age && { age: parseInt(age) }),
            ...(designation && { designation }),
            ...(location && { location }),
          },
          $setOnInsert: {
            isActive: true,
            isLocked: false,
            createdAt: ist.utc,
          },
        },
        { upsert: true },
      );

      await auditLog(
        'ENROLL_SUCCESS',
        req.user.userId,
        workerId,
        {
          firstName,
          lastName,
          designation,
          faceId: faceRecord.FaceId,
          confidence: faceRecord.Confidence,
        },
        req,
      );

      logger.info(
        `Worker enrolled: ${workerId} by ${req.user.userId} (${req.user.role}) at ${ist.localTime} IST`,
      );

      return sendSuccess(res, {
        message: 'Worker enrolled successfully',
        workerId: workerId,
        enrolledBy: req.user.userId,
      });
    } catch (error) {
      await auditLog(
        'ENROLL_ERROR',
        req.user?.userId,
        req.body?.workerId,
        { error: error.message },
        req,
      );
      return sendError(res, 500, 'Enrollment failed', error);
    }
  },
);

// ============================================================================
// ROUTE: POST /api/recognize (Public - Workers face IN/OUT)
// NO AUTH NEEDED — NO FRONTEND CHANGES NEEDED
// Server handles IST conversion automatically
// ============================================================================
app.post('/api/recognize', upload.single('image'), async (req, res) => {
  try {
    const imageBuffer = req.file?.buffer;
    const { status } = req.body;

    // Parse location
    let location = req.body.location;
    if (typeof location === 'string') {
      try {
        location = JSON.parse(location);
      } catch (e) {
        /* keep as is */
      }
    }

    // 1. Validation
    if (!imageBuffer) return sendError(res, 400, 'No image provided.');

    const normalizedStatus = status ? status.toUpperCase() : 'IN';
    if (normalizedStatus !== 'IN' && normalizedStatus !== 'OUT') {
      return sendError(res, 400, "Status must be 'IN' or 'OUT'.");
    }

    // ✅ Get IST timestamp — no frontend data needed
    const ist = getISTTimestamp();

    const db = await connectToMongo();

    // 2. Search face in AWS
    const searchResult = await searchFaceByImage(imageBuffer);

    if (!searchResult.FaceMatches || searchResult.FaceMatches.length === 0) {
      await auditLog(
        'RECOGNIZE_FAILED',
        'SYSTEM',
        null,
        { reason: 'Face not recognized' },
        req,
      );
      return sendError(res, 404, 'Face not recognized. Please contact staff.');
    }

    const match = searchResult.FaceMatches[0];
    const similarity = match.Similarity;
    const matchedWorkerId = match.Face.ExternalImageId;

    if (similarity < config.FACE_VERIFICATION_THRESHOLD) {
      await auditLog(
        'RECOGNIZE_LOW_CONFIDENCE',
        'SYSTEM',
        matchedWorkerId,
        { similarity: Math.round(similarity) },
        req,
      );
      return sendError(res, 401, `Low confidence: ${Math.round(similarity)}%.`);
    }

    // 3. Get worker from DB
    const worker = await db
      .collection(config.COLLECTIONS.WORKERS)
      .findOne({ workerId: matchedWorkerId });

    if (!worker) {
      return sendError(
        res,
        404,
        'Worker found in AWS but not in database. Contact admin.',
      );
    }

    if (!worker.isActive) {
      return sendError(res, 403, 'Your account is deactivated. Contact admin.');
    }

    if (worker.isLocked) {
      return sendError(res, 403, 'Your account is locked. Contact admin.');
    }

    // ✅ 4. Check duplicate — IST day boundaries (midnight to midnight IST)
    const istStartOfDay = getISTStartOfDay();
    const istEndOfDay = getISTEndOfDay();

    const existingLog = await db
      .collection(config.COLLECTIONS.ATTENDANCE)
      .findOne({
        workerId: matchedWorkerId,
        status: normalizedStatus,
        'timestamps.utc': { $gte: istStartOfDay, $lte: istEndOfDay },
      });

    if (existingLog) {
      return sendError(
        res,
        409,
        `Already marked ${normalizedStatus} today at ${existingLog.timestamps?.localTime || 'earlier'}.`,
      );
    }

    // ✅ 5. Insert attendance with IST timestamps
    await db.collection(config.COLLECTIONS.ATTENDANCE).insertOne({
      workerId: matchedWorkerId,
      workerName: `${worker.firstName} ${worker.lastName}`,
      status: normalizedStatus,
      similarity: Math.round(similarity),
      location: location || null,

      // ✅ STANDARDIZED IST TIMESTAMP
      timestamps: {
        utc: ist.utc,
        iso: ist.iso,
        localDate: ist.localDate,
        localTime: ist.localTime,
        timezone: ist.timezone,
      },

      createdAt: ist.utc,
    });

    // 6. Update worker's last status
    await db.collection(config.COLLECTIONS.WORKERS).updateOne(
      { workerId: matchedWorkerId },
      {
        $set: {
          lastStatus: normalizedStatus,
          lastStatusAt: ist.utc,
          lastStatusLocal: ist.localTime,
        },
      },
    );

    // 7. Audit Log
    await auditLog(
      `ATTENDANCE_${normalizedStatus}`,
      'SYSTEM',
      matchedWorkerId,
      {
        similarity: Math.round(similarity),
        location,
        workerName: `${worker.firstName} ${worker.lastName}`,
        localTime: ist.localTime,
        localDate: ist.localDate,
      },
      req,
    );

    logger.info(
      `Attendance: ${matchedWorkerId} → ${normalizedStatus} at ${ist.localTime} IST [${Math.round(similarity)}%]`,
    );

    // ✅ Return IST time to frontend
    return sendSuccess(res, {
      message: `Marked ${normalizedStatus} successfully`,
      workerId: matchedWorkerId,
      workerName: `${worker.firstName} ${worker.lastName}`,
      status: normalizedStatus,
      similarity: Math.round(similarity),
      time: ist.localTime,
      date: ist.localDate,
    });
  } catch (error) {
    await auditLog(
      'RECOGNIZE_ERROR',
      'SYSTEM',
      null,
      { error: error.message },
      req,
    );
    return sendError(res, 500, 'Recognition failed', error);
  }
});

// ============================================================================
// ROUTE: POST /api/reports (Admin ONLY - Date Range, IST-aware)
// ============================================================================
app.post(
  '/api/reports',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { startDate, endDate } = req.body;

      if (!startDate || !endDate) {
        return sendError(res, 400, 'Start date and end date are required.');
      }

      const db = await connectToMongo();

      // ✅ Parse as IST boundaries
      const startIST = new Date(`${startDate}T00:00:00${IST_OFFSET}`);
      const endIST = new Date(`${endDate}T23:59:59.999${IST_OFFSET}`);

      const logs = await db
        .collection(config.COLLECTIONS.ATTENDANCE)
        .find({
          'timestamps.utc': { $gte: startIST, $lte: endIST },
        })
        .sort({ 'timestamps.utc': -1 })
        .toArray();

      await auditLog(
        'REPORT_VIEWED',
        req.user.userId,
        null,
        {
          type: 'date_range',
          startDate,
          endDate,
          recordCount: logs.length,
        },
        req,
      );

      return sendSuccess(res, { data: logs, count: logs.length });
    } catch (error) {
      return sendError(res, 500, 'Failed to generate report', error);
    }
  },
);

// ============================================================================
// ROUTE: POST /api/reports/month (Admin ONLY - Monthly, IST-aware)
// ============================================================================
app.post(
  '/api/reports/month',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { date: monthName, year } = req.body;
      const targetYear = year ? parseInt(year) : new Date().getFullYear();

      if (!monthName) {
        return sendError(res, 400, 'Month name is required.');
      }

      const monthIndex = new Date(`${monthName} 1, ${targetYear}`).getMonth();
      if (isNaN(monthIndex)) {
        return sendError(res, 400, 'Invalid month name.');
      }

      const db = await connectToMongo();

      // ✅ IST month boundaries
      const monthStr = String(monthIndex + 1).padStart(2, '0');
      const lastDay = new Date(targetYear, monthIndex + 1, 0).getDate();

      const startIST = new Date(
        `${targetYear}-${monthStr}-01T00:00:00${IST_OFFSET}`,
      );
      const endIST = new Date(
        `${targetYear}-${monthStr}-${lastDay}T23:59:59.999${IST_OFFSET}`,
      );

      const logs = await db
        .collection(config.COLLECTIONS.ATTENDANCE)
        .find({
          'timestamps.utc': { $gte: startIST, $lte: endIST },
        })
        .sort({ 'timestamps.utc': -1 })
        .toArray();

      await auditLog(
        'REPORT_VIEWED',
        req.user.userId,
        null,
        {
          type: 'monthly',
          month: monthName,
          year: targetYear,
          recordCount: logs.length,
        },
        req,
      );

      return sendSuccess(res, { data: logs, count: logs.length });
    } catch (error) {
      return sendError(res, 500, 'Failed to generate report', error);
    }
  },
);

// ============================================================================
// ROUTE: POST /api/workers (Admin ONLY - List all workers)
// ============================================================================
app.post(
  '/api/workers',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const db = await connectToMongo();
      const workers = await db
        .collection(config.COLLECTIONS.WORKERS)
        .find({}, { projection: { awsFaceId: 0, enrollmentConfidence: 0 } })
        .sort({ createdAt: -1 })
        .toArray();

      return sendSuccess(res, { workers, count: workers.length });
    } catch (error) {
      return sendError(res, 500, 'Failed to retrieve workers', error);
    }
  },
);

// ============================================================================
// ROUTE: POST /api/worker/info (Admin ONLY - Single worker's attendance)
// ============================================================================
app.post(
  '/api/worker/info',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { workerId } = req.body;

      if (!workerId) {
        return sendError(res, 400, 'Worker ID is required.');
      }

      const db = await connectToMongo();

      const worker = await db
        .collection(config.COLLECTIONS.WORKERS)
        .findOne({ workerId }, { projection: { awsFaceId: 0 } });

      if (!worker) {
        return sendError(res, 404, 'Worker not found.');
      }

      const attendance = await db
        .collection(config.COLLECTIONS.ATTENDANCE)
        .find({ workerId })
        .sort({ 'timestamps.utc': -1 })
        .toArray();

      await auditLog(
        'WORKER_INFO_VIEWED',
        req.user.userId,
        workerId,
        { recordCount: attendance.length },
        req,
      );

      return sendSuccess(res, { worker, attendance, count: attendance.length });
    } catch (error) {
      return sendError(res, 500, 'Failed to retrieve worker info', error);
    }
  },
);

// ============================================================================
// ROUTE: POST /api/audit (Admin ONLY - View audit logs)
// ============================================================================
app.post('/api/audit', authMiddleware, checkRole('admin'), async (req, res) => {
  try {
    const { startDate, endDate, action, limit = 100 } = req.body;

    const db = await connectToMongo();

    const query = {};

    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(`${startDate}T00:00:00${IST_OFFSET}`),
        $lte: new Date(`${endDate}T23:59:59.999${IST_OFFSET}`),
      };
    }

    if (action) {
      query.action = action;
    }

    const logs = await db
      .collection(config.COLLECTIONS.AUDIT)
      .find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .toArray();

    return sendSuccess(res, { logs, count: logs.length });
  } catch (error) {
    return sendError(res, 500, 'Failed to retrieve audit logs', error);
  }
});

// ============================================================================
// ROUTE: PUT /api/admin/workers/:workerId/lock (Admin ONLY)
// ============================================================================
app.put(
  '/api/admin/workers/:workerId/lock',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { workerId } = req.params;
      const { isLocked } = req.body;

      const db = await connectToMongo();
      const ist = getISTTimestamp();

      const worker = await db
        .collection(config.COLLECTIONS.WORKERS)
        .findOne({ workerId });

      if (!worker) return sendError(res, 404, 'Worker not found.');

      await db
        .collection(config.COLLECTIONS.WORKERS)
        .updateOne({ workerId }, { $set: { isLocked, updatedAt: ist.utc } });

      await auditLog(
        isLocked ? 'WORKER_LOCKED' : 'WORKER_UNLOCKED',
        req.user.userId,
        workerId,
        { previousState: worker.isLocked },
        req,
      );

      return sendSuccess(res, {
        message: `Worker ${isLocked ? 'locked' : 'unlocked'} successfully.`,
      });
    } catch (error) {
      return sendError(res, 500, 'Failed to update lock status', error);
    }
  },
);

// ============================================================================
// ERROR HANDLER
// ============================================================================
app.use((err, _req, res, _next) => {
  logger.error('Unhandled error:', err);
  return res
    .status(500)
    .json({ success: false, message: 'Internal Server Error' });
});

// ============================================================================
// START SERVER
// ============================================================================
app.listen(config.PORT, '0.0.0.0', async () => {
  const ist = getISTTimestamp();
  logger.info(
    `Server running on port ${config.PORT} (${config.NODE_ENV}) | IST: ${ist.localDate} ${ist.localTime}`,
  );
});

module.exports = app;
