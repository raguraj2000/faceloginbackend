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
};

// ============================================================================
// INITIALIZE EXPRESS & MIDDLEWARE
// ============================================================================
const app = express();

// Helper: Check if two dates are the same day
function isSameDay(date1, date2) {
  const d1 = new Date(date1);
  const d2 = new Date(date2);
  return (
    d1.getFullYear() === d2.getFullYear() &&
    d1.getMonth() === d2.getMonth() &&
    d1.getDate() === d2.getDate()
  );
}

module.exports = { isSameDay };

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.FILE_SIZE_LIMIT },
  fileFilter: (_req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG and PNG allowed.'));
    }
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

app.use((req, _res, next) => {
  logger.info(`[${req.method}] ${req.path}`, { body: req.body });
  next();
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

async function authMiddleware(req, res, next) {
  console.log('authMiddleware', req.headers);

  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return sendError(res, 401, 'Authentication token required.');

    const decoded = jwt.verify(token, config.JWT_SECRET);
    const db = await connectToMongo();

    // Find user in DB
    const user = await db
      .collection('users')
      .findOne({ userId: decoded.userId });
    if (!user) return sendError(res, 404, 'User not found.');

    // Check Active/Locked status
    if (!user.isActive) return sendError(res, 403, 'Account deactivated.');
    if (user.isLocked) return sendError(res, 403, 'Account locked.');

    req.user = user;
    next();
  } catch (error) {
    sendError(res, 401, 'Invalid token.', error);
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
// HELPERS
// ============================================================================
function validateRequiredFields(data, fields) {
  const missing = fields.filter((field) => !data[field]);
  if (missing.length > 0) throw new Error(`Missing: ${missing.join(', ')}`);
}

function sendError(res, statusCode, message, error = null) {
  logger.error(message, error);
  res.status(statusCode).json({
    success: false,
    message,
    ...(config.NODE_ENV === 'development' &&
      error && { details: error.message }),
  });
}

function sendSuccess(res, data, statusCode = 200) {
  res.status(statusCode).json({ success: true, ...data });
}

async function searchFaceByImage(imageBuffer) {
  const params = {
    CollectionId: config.AWS.COLLECTION_ID,
    Image: { Bytes: imageBuffer },
    MaxFaces: 1,
    FaceMatchThreshold: config.FACE_MATCH_THRESHOLD,
  };
  return await rekognition.searchFacesByImage(params).promise();
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

function generateJWT(payload) {
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRY });
}

// ============================================================================
// ROUTES
// ============================================================================

/**
 * POST /api/signin - Login for Admin and Staff ONLY
 *
 * Logic:
 * 1. Verify credentials with Clerk.
 * 2. Check Clerk privateMetadata for role.
 * 3. If role is 'user', DENY access (Users cannot signin via password).
 * 4. Upsert to MongoDB with correct role.
 */
app.post('/api/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    validateRequiredFields({ email, password }, ['email', 'password']);

    // 1. Verify with Clerk
    const users = await clerkClient.users.getUserList({
      emailAddress: [email],
    });
    console.log('/api/signin,users', users);

    if (!users?.length) return sendError(res, 401, 'Invalid credentials.');

    const user = users[0];
    if (user.locked) return sendError(res, 403, 'Account locked.');

    const { verified } = await clerkClient.users.verifyPassword({
      userId: user.id,
      password,
    });
    if (!verified) return sendError(res, 401, 'Invalid credentials.');

    // 2. Determine Role from Clerk Private Metadata
    // Default to 'staff' if not found, as requested.
    let role = user.privateMetadata?.role || 'staff';

    // SECURITY: Deny access if role is explicitly 'user'
    // Users should only use face recognition to mark attendance (in/out), not login.
    if (role === 'user') {
      logger.warn(
        `Login denied for user ${email} because role is 'user'. Users must use Face Recognition.`,
      );
      return sendError(
        res,
        403,
        'Access Denied. Regular users cannot sign in with a password. Please use the Face Recognition terminal.',
      );
    }

    const db = await connectToMongo();

    // 3. Upsert (Update or Insert) User to MongoDB
    // We ensure the DB role matches the Clerk Metadata role
    await db.collection('users').updateOne(
      { userId: user.id },
      {
        $setOnInsert: {
          isActive: true,
          isLocked: false,
          enrolledAt: null,
          createdAt: new Date(),
        },
        $set: {
          role: role,
          updatedAt: new Date(),
        },
      },
      { upsert: true },
    );

    // Fetch the updated user to generate token
    const dbUser = await db.collection('users').findOne({ userId: user.id });

    // 4. Generate Token
    const token = generateJWT({
      userId: user.id,
      email: user.emailAddresses[0]?.emailAddress,
      role: dbUser.role,
    });

    logger.info(`Admin/Staff logged in: ${email} (${role})`);
    sendSuccess(res, {
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.emailAddresses[0]?.emailAddress,
        firstName: user.firstName,
        lastName: user.lastName,
        role: dbUser.role,
      },
    });
  } catch (error) {
    sendError(res, 401, 'Authentication failed', error);
  }
});

/**
 * POST /api/enroll - Enroll a face (Admin & Staff only)
 * Logic: Staff can only enroll 'user' role. Admin can enroll anyone.
 */
// ============================================================================
// ROUTE: /api/enroll
// ============================================================================
app.post(
  '/api/enroll',
  authMiddleware,
  checkRole('admin', 'staff'),
  upload.single('image'),
  async (req, res) => {
    try {
      const { userid, firstName, lastName, role, age, designation, location } =
        req.body;
      const imageBuffer = req.file?.buffer;

      // 1. Basic Validation
      validateRequiredFields({ userid, imageBuffer }, [
        'userid',
        'imageBuffer',
      ]);

      const db = await connectToMongo();

      // 2. CHECK AWS FACE COLLECTION FIRST
      // "check aws face id by face, if already registered it has faceid"
      const searchResult = await searchFaceByImage(imageBuffer);

      if (searchResult.FaceMatches && searchResult.FaceMatches.length > 0) {
        const existingExternalId =
          searchResult.FaceMatches[0].Face.ExternalImageId;
        return sendError(
          res,
          409,
          `This face is already registered to user ID: ${existingExternalId}.`,
        );
      }

      // 3. FIND USER IN DB
      const targetUser = await db
        .collection('users')
        .findOne({ userId: userid });

      // 4. CHECK IF ALREADY ENROLLED
      if (targetUser && targetUser.awsFaceId) {
        return sendError(res, 409, `User ${userid} is already enrolled.`);
      }

      // 5. INDEX FACE IN AWS
      const indexResult = await indexFaceInCollection(imageBuffer, userid);

      if (!indexResult.FaceRecords || indexResult.FaceRecords.length === 0) {
        return sendError(res, 400, 'No face detected in image.');
      }

      const faceRecord = indexResult.FaceRecords[0].Face;

      // 6. UPSERT TO DATABASE
      // "if not add details in db" -> If user exists, update. If not, insert.
      await db.collection('users').updateOne(
        { userId: userid },
        {
          $set: {
            // Update these fields always
            awsFaceId: faceRecord.FaceId,
            enrollmentConfidence: faceRecord.Confidence,
            enrolledAt: new Date(),
            ...(age && { age }),
            ...(designation && { designation }),
            ...(location && { location }),
            // Also update name/role in case they changed
            ...(firstName && { firstName }),
            ...(lastName && { lastName }),
            ...(role && { role }),
          },
          $setOnInsert: {
            // Only insert these if creating NEW user
            isActive: true,
            isLocked: false,
            createdAt: new Date(),
          },
        },
        { upsert: true }, // <--- THIS IS THE KEY. It creates if not found.
      );

      logger.info(`User enrolled: ${userid} by ${req.user.userId}`);

      sendSuccess(res, {
        message: 'Face enrolled successfully',
        userId: userid,
      });
    } catch (error) {
      sendError(res, 500, 'Enrollment failed', error);
    }
  },
);

// ============================================================================
// ROUTE: /api/userinfo
// ============================================================================
app.post('/api/userinfo', authMiddleware, async (req, res) => {
  try {
    const { userid } = req.body;

    if (!userid) {
      return sendError(res, 400, 'User ID is required');
    }

    // LOGIC FIX:
    // Since we removed authMiddleware from /recognize, 'user' role accounts
    // literally CANNOT have a token to access this route.
    // Only 'admin' and 'staff' can be authenticated here.
    // Therefore, we allow them to see any logs.

    const db = await connectToMongo();
    const logs = await db
      .collection('logger')
      .find({ userId: userid }, { projection: { awsFaceId: 0 } }) // Hide awsFaceId for privacy
      .sort({ createdAt: -1 })
      .toArray();

    sendSuccess(res, { logs, count: logs.length });
  } catch (error) {
    sendError(res, 500, 'Failed to retrieve info', error);
  }
});

/**
 * POST /api/recognize - Mark Attendance (Admin, Staff, User)
 * Logic: Uses Face Recognition. Checks IN/OUT logic.
 */
app.post(
  '/api/recognize',
  // authMiddleware, // <--- Kept commented out for public access
  upload.single('image'),
  async (req, res) => {
    try {
      const imageBuffer = req.file?.buffer;
      const { status } = req.body;
      // Parse location if it comes as a stringified JSON from frontend
      let location = req.body.location;
      if (typeof location === 'string') {
        try {
          location = JSON.parse(location);
        } catch (e) {
          console.warn('Failed to parse location string, keeping as is');
        }
      }

      // 1. Validation
      if (!imageBuffer) return sendError(res, 400, 'No image provided');

      const normalizedStatus = status ? status.toUpperCase() : 'IN';
      if (normalizedStatus !== 'IN' && normalizedStatus !== 'OUT') {
        return sendError(res, 400, "Status must be 'IN' or 'OUT'.");
      }

      const db = await connectToMongo();

      // 2. Search AWS
      const searchResult = await searchFaceByImage(imageBuffer);
      if (!searchResult.FaceMatches || searchResult.FaceMatches.length === 0) {
        return sendError(res, 404, 'Face not recognized.');
      }

      const match = searchResult.FaceMatches[0];
      const similarity = match.Similarity;
      // FIX: Use ExternalImageId (which should be your userId string)
      const matchedUserId = match.Face.ExternalImageId;

      if (similarity < config.FACE_VERIFICATION_THRESHOLD) {
        return sendError(
          res,
          401,
          `Low confidence: ${Math.round(similarity)}%.`,
        );
      }

      // 3. Get User from DB using the ID found in AWS
      const user = await db
        .collection('users')
        .findOne({ userId: matchedUserId });

      if (!user) {
        return sendError(res, 404, 'User found in AWS but not in Database.');
      }

      // 4. Check Duplicates Today (Use the ID from the Face, not the Token)
      const startOfDay = new Date();
      startOfDay.setHours(0, 0, 0, 0);

      const existingLog = await db.collection('logger').findOne({
        userId: matchedUserId, // <--- FIX: Use matchedUserId instead of req.user.userId
        status: normalizedStatus,
        createdAt: { $gte: startOfDay },
      });

      if (existingLog) {
        return sendError(
          res,
          409,
          `Already marked ${normalizedStatus} today at ${new Date(existingLog.createdAt).toLocaleTimeString()}.`,
        );
      }

      // 5. Update User Status
      await db.collection('users').updateOne(
        { userId: matchedUserId }, // <--- FIX: Use matchedUserId
        { $set: { lastStatus: normalizedStatus, lastStatusAt: new Date() } },
      );

      // 6. Log Attendance
      await db.collection('logger').insertOne({
        userId: matchedUserId, // <--- FIX: Use matchedUserId
        awsFaceId: user.awsFaceId, // Get ID from DB user object
        status: normalizedStatus,
        createdAt: new Date(),
        location: location || null,
        similarity: Math.round(similarity),
      });

      // FIX: Use matchedUserId in logger (req.user is undefined)
      logger.info(`Attendance: ${matchedUserId} -> ${normalizedStatus}`);

      sendSuccess(res, {
        message: `Marked ${normalizedStatus} successfully`,
        userId: matchedUserId,
        status: normalizedStatus,
        similarity: Math.round(similarity),
      });
    } catch (error) {
      sendError(res, 500, 'Recognition failed', error);
    }
  },
);
// ============================================================================
// ADMIN ONLY ROUTES
// ============================================================================
app.post('/api/reports', async (req, res) => {
  try {
    const { startDate, endDate } = req.body;

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ success: false, error: 'Date range is required' });
    }

    const db = await connectToMongo();

    // 1. Create date range
    const startOfDay = new Date(startDate);
    startOfDay.setHours(0, 0, 0, 0);

    const endOfDay = new Date(endDate);
    endOfDay.setHours(23, 59, 59, 999);

    // 2. Get Logs (Directly filter by date, no need to fetch all users first)
    // FIX: Changed 'creadedAt' to 'createdAt'
    const logs = await db
      .collection('logger')
      .find(
        {
          createdAt: {
            // <--- FIXED TYPO
            $gte: startOfDay,
            $lte: endOfDay,
          },
        },
        { projection: { awsFaceId: 0 } },
      )
      .sort({ createdAt: -1 }) // Sort newest first
      .toArray();

    // 3. Get User Details for the logs found (Optimization)
    // Extract unique user IDs from the logs
    const uniqueUserIds = [...new Set(logs.map((log) => log.userId))];

    // Fetch details ONLY for these users
    const userDetails = await db
      .collection('users')
      .find({ userId: { $in: uniqueUserIds } })
      .project({ _id: 0, awsFaceId: 0, password: 0 }) // Hide sensitive fields
      .toArray();

    // 4. Combine Data (Map logs to user names)
    const reportData = logs.map((log) => {
      const user = userDetails.find((u) => u.userId === log.userId);
      return {
        ...log,
        userName: user
          ? `${user.firstName || ''} ${user.lastName || ''}`.trim() ||
            user.userId
          : 'Unknown',
        userRole: user ? user.role : 'unknown',
      };
    });
    console.log('api/reportsdayreportData', reportData);
    res.json({
      success: true,
      data: reportData,
    });
  } catch (error) {
    console.error('Reports error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/reports/month', async (req, res) => {
  try {
    const { date: monthName, year } = req.body;

    // Default to current year if not provided
    const targetYear = year ? parseInt(year) : new Date().getFullYear();

    if (!monthName) {
      return res
        .status(400)
        .json({ success: false, error: 'Month name is required' });
    }

    const db = await connectToMongo();

    // 1. Convert month name to index (e.g. "January" -> 0)
    const monthIndex = new Date(`${monthName} 1, ${targetYear}`).getMonth();
    if (isNaN(monthIndex)) {
      return res
        .status(400)
        .json({ success: false, error: 'Invalid month name' });
    }

    // 2. Calculate start and end of month
    const startOfMonth = new Date(targetYear, monthIndex, 1);
    const endOfMonth = new Date(targetYear, monthIndex + 1, 0, 23, 59, 59, 999);

    // 3. Get Logs
    // FIX: Changed 'creadedAt' to 'createdAt'
    const logs = await db
      .collection('logger')
      .find(
        {
          createdAt: {
            // <--- FIXED TYPO
            $gte: startOfMonth,
            $lte: endOfMonth,
          },
        },
        { projection: { awsFaceId: 0 } },
      )
      .sort({ createdAt: -1 })
      .toArray();

    // 4. Get User Details
    const uniqueUserIds = [...new Set(logs.map((log) => log.userId))];
    const userDetails = await db
      .collection('users')
      .find({ userId: { $in: uniqueUserIds } })
      .project({ _id: 0, awsFaceId: 0 })
      .toArray();

    // 5. Combine Data
    const reportData = logs.map((log) => {
      const user = userDetails.find((u) => u.userId === log.userId);
      return {
        ...log,
        userName: user
          ? `${user.firstName || ''} ${user.lastName || ''}`.trim() ||
            user.userId
          : 'Unknown',
        userRole: user ? user.role : 'unknown',
      };
    });
    console.log('reportData', reportData);

    res.json({
      success: true,
      data: reportData,
    });
  } catch (error) {
    console.error('Reports error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post(
  '/api/listusers',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const db = await connectToMongo();
      const users = await db
        .collection('users')
        .find({}, { projection: { awsFaceId: 0, enrollmentConfidence: 0 } })
        .sort({ createdAt: -1 })
        .toArray();

      const formattedUsers = users.map((u) => ({
        ...u,
        createdAt: u.createdAt ? new Date(u.createdAt).toLocaleString() : null,
      }));

      sendSuccess(res, { users: formattedUsers, count: users.length });
    } catch (error) {
      sendError(res, 500, 'Failed to retrieve users', error);
    }
  },
);

// app.post('/api/userinfo', authMiddleware, async (req, res) => {
//   try {
//     const { userid } = req.body;
//     // Admin/Staff can see any. User can only see self.
//     if (req.user.role === 'user' && req.user.userId !== userid) {
//       return sendError(res, 403, 'Access denied.');
//     }

//     const db = await connectToMongo();
//     const logs = await db
//       .collection('logger')
//       .find({ userId: userid }, { projection: { awsFaceId: 0 } })
//       .sort({ createdAt: -1 })
//       .toArray();

//     sendSuccess(res, { logs, count: logs.length });
//   } catch (error) {
//     sendError(res, 500, 'Failed to retrieve info', error);
//   }
// });

// Admin: Create User
app.post(
  '/api/admin/users/create',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { emailAddress, firstName, lastName, password, role } = req.body;
      validateRequiredFields({ emailAddress, firstName, lastName, password }, [
        'emailAddress',
        'firstName',
        'lastName',
        'password',
      ]);

      // Set role in Clerk Private Metadata
      const clerkUser = await clerkClient.users.createUser({
        emailAddress: [emailAddress],
        firstName,
        lastName,
        password,
        privateMetadata: { role: role || 'user' }, // Default to user if not specified
      });

      const db = await connectToMongo();
      await db.collection('users').insertOne({
        userId: clerkUser.id,
        role: role || 'user',
        isActive: true,
        isLocked: false,
        enrolledAt: null,
        createdAt: new Date(),
      });

      sendSuccess(res, { message: 'User created', userId: clerkUser.id }, 201);
    } catch (error) {
      if (error.errors) return sendError(res, 400, error.errors[0].message);
      sendError(res, 500, 'Failed to create user', error);
    }
  },
);

// Admin: Update Role
app.put(
  '/api/admin/users/:userId/role',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { role } = req.body;
      const validRoles = ['user', 'staff', 'admin'];
      if (!validRoles.includes(role))
        return sendError(res, 400, 'Invalid role');

      const db = await connectToMongo();
      await db.collection('users').updateOne({ userId }, { $set: { role } });

      // Update Clerk metadata as well to keep in sync
      await clerkClient.users.updateUser(userId, { privateMetadata: { role } });

      sendSuccess(res, { message: 'Role updated' });
    } catch (error) {
      sendError(res, 500, 'Failed to update role', error);
    }
  },
);

// Admin: Lock/Unlock
app.put(
  '/api/admin/users/:userId/lock',
  authMiddleware,
  checkRole('admin'),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { isLocked } = req.body;

      const db = await connectToMongo();
      const user = await db.collection('users').findOne({ userId });
      if (!user) return sendError(res, 404, 'User not found');

      // Sync Lock Status
      if (user.role === 'admin' || user.role === 'staff') {
        if (isLocked) await clerkClient.users.lockUser(userId);
        else await clerkClient.users.unlockUser(userId);
      } else {
        await db
          .collection('users')
          .updateOne({ userId }, { $set: { isLocked } });
      }

      sendSuccess(res, { message: `User ${isLocked ? 'locked' : 'unlocked'}` });
    } catch (error) {
      sendError(res, 500, 'Failed to update lock status', error);
    }
  },
);

// ============================================================================
// SERVER STARTUP
// ============================================================================
app.use((err, _req, res, _next) => {
  logger.error(err);
  res.status(500).json({ success: false, message: 'Server Error' });
});

const server = app.listen(config.PORT, '0.0.0.0', async () => {
  logger.info(`Server running on port ${config.PORT}`);
  // 2. Delete this batch (max 100 face IDs per call)
  // const listParams = {
  //   CollectionId: config.AWS.COLLECTION_ID,
  //   MaxResults: 100,
  // };
  // const listResponse = await rekognition.listFaces(listParams).promise();

  // const faceIds = listResponse.Faces.map((face) => face.FaceId);
  // console.log('&&&&&&&&&&&&&&&&&&&&&faceid', faceIds);
  // const deleteParams = {
  //   CollectionId: config.AWS.COLLECTION_ID,
  //   FaceIds: faceIds,
  // };

  // const deleteResponse = await rekognition.deleteFaces(deleteParams).promise();

  // const deletedThisBatch = deleteResponse.DeletedFaces.length;

  // console.log(
  //   `Deleted ${deletedThisBatch} faces (total so far: ${deleteResponse})`,
  // );
});

module.exports = app;

