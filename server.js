

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const isProduction = process.env.NODE_ENV === 'production';

// ---------- DATABASE ----------

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction
    ? { rejectUnauthorized: false }
    : false
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

// ---------- SECURITY & MIDDLEWARE ----------

// Applicant guard: login/finalize store the USERS table id in the session.
// Applicant routes need the APPLICANTS table id, so look it up here (linked by identity).
const requireApplicant = async (req, res, next) => {
  try {
    if (!req.session || !req.session.userId || req.session.role !== 'applicant') {
      return res.status(401).json({ error: 'Unauthorized. Please log in as an applicant.' });
    }
    const result = await pool.query(
      `SELECT a.id
         FROM applicants a
         JOIN users u ON u.identity = a.identity OR u.email = a.email
        WHERE u.id = $1
        LIMIT 1`,
      [req.session.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Applicant record not found for this account.' });
    }
    req.user = { id: result.rows[0].id, userId: req.session.userId, identity: req.session.identity };
    return next();
  } catch (err) {
    console.error('requireApplicant error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
};


app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: 'cross-origin'
    }
  })
);

app.use(
  cors({
    origin: [
      'http://localhost:3001',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:5173',
      'http://localhost:3000'
    ],
    credentials: true,
    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS'
    ],
    allowedHeaders: [
      'Content-Type',
      'Authorization'
    ]
  })
);

app.use(express.json({ limit: '1mb' }));

// Serve frontend files from public/
app.use(express.static(path.join(__dirname, 'public')));

// ---------- SESSION ----------

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    name: isProduction
      ? '__Host-tfism.sid'
      : 'tfism.sid',
    secret:
      process.env.SESSION_SECRET ||
      'change-this-secret-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
      path: '/'
    }
  })
);

// ---------- RATE LIMITING ----------

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.'
  }
});

app.use(limiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts. Please try again later.'
  }
});


// ---------- DATABASE HEALTH ----------

app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT current_database() AS database, NOW() AS time'
    );

    res.json({
      ok: true,
      database: result.rows[0].database,
      time: result.rows[0].time
    });
  } catch (err) {
    console.error('Health check error:', err);

    res.status(500).json({
      ok: false,
      database: 'disconnected'
    });
  }
});

// ---------- APPLICATION DRAFT GUARD ----------

function requireApplicationDraft(req, res, next) {
  const applicantId = req.session.applicationDraftId;

  if (!applicantId) {
    return res.status(401).json({
      error:
        'Your application session has expired. Please restart or continue from Step 1.'
    });
  }

  req.applicantDraftId = applicantId;
  next();
}

// ---------- APPLICANT AUTH GUARD ----------

function requireApplicantAuth(req, res, next) {
  if (
    !req.session.userId ||
    req.session.role !== 'applicant'
  ) {
    return res.status(401).json({
      error: 'Not authenticated as applicant.'
    });
  }

  next();
}

// ---------- ADMIN GUARD ----------

function requireAdmin(req, res, next) {
  if (
    !req.session.userId ||
    req.session.role !== 'admin'
  ) {
    return res.status(403).json({
      error: 'Admin access required.'
    });
  }

  next();
}
// ---------- FILE UPLOAD SETUP ----------

const privateUploadsDir = path.join(
  __dirname,
  'uploads',
  'private'
);

if (!fs.existsSync(privateUploadsDir)) {
  fs.mkdirSync(privateUploadsDir, {
    recursive: true
  });
}

const admissionUploadsDir = path.join(
  privateUploadsDir,
  'admission'
);

if (!fs.existsSync(admissionUploadsDir)) {
  fs.mkdirSync(admissionUploadsDir, {
    recursive: true
  });
}

const allowedDocuments = new Set([
  'application/pdf',
  'image/jpeg',
  'image/png'
]);

const allowedPassportImages = new Set([
  'image/jpeg',
  'image/png'
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, admissionUploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, `admission-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPassport = file.fieldname === 'passportFile';

    const allowedTypes = isPassport
      ? allowedPassportImages
      : allowedDocuments;

    if (!allowedTypes.has(file.mimetype)) {
      return cb(
        new Error(
          isPassport
            ? 'Passport photo must be a JPG or PNG image.'
            : 'Documents must be PDF, JPG, or PNG files.'
        )
      );
    }

    cb(null, true);
  }
});

// Generate cryptographically secure verification hash for the letter content
function generateDocumentHash(htmlContent) {
  return crypto.createHash('sha256').update(htmlContent).digest('hex');
}

// Advanced HTML Template with Watermarking and Security Metadata
function generateAdvancedAdmissionLetterHtml(applicant) {
  const generatedDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  
  const uniqueReference = `TFISM-ADM-${applicant.id}-${Date.now().toString().slice(-6)}`;
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Official Admission Letter - ${escapeHtml(applicant.full_name)}</title>
      <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #333; line-height: 1.6; margin: 0; padding: 40px; }
        .header { text-align: center; border-bottom: 2px solid #1a365d; padding-bottom: 20px; margin-bottom: 30px; }
        .watermark { position: fixed; top: 35%; left: 20%; opacity: 0.04; font-size: 90px; color: #1a365d; transform: rotate(-30deg); z-index: -1000; font-weight: bold; pointer-events: none; }
        .content { max-width: 800px; margin: 0 auto; background: #fff; padding: 20px; }
        .footer { margin-top: 50px; border-top: 1px solid #e2e8f0; padding-top: 20px; font-size: 12px; color: #718096; display: flex; justify-content: space-between; }
        .badge { background: #edf2f7; padding: 4px 8px; border-radius: 4px; font-family: monospace; }
      </style>
    </head>
    <body>
      <div class="watermark">OFFICIAL DOCUMENT</div>
      <div class="content">
        <div class="header">
          <h2>INSTITUTE OF TECHNOLOGY & MANAGEMENT</h2>
          <p>Office of the Registrar | Department of Admissions</p>
        </div>
        
        <p>Date: <strong>${generatedDate}</strong></p>
        <p>Ref ID: <span class="badge">${uniqueReference}</span></p>
        
        <h3>Dear ${escapeHtml(applicant.full_name)},</h3>
        
        <p>We are delighted to formally offer you provisional admission into the <strong>${escapeHtml(applicant.program_name)}</strong> (${escapeHtml(applicant.program_code)}) program for the <strong>${escapeHtml(applicant.preferred_session)}</strong> session at <strong>${escapeHtml(applicant.entry_level)}</strong> level.</p>
        
        <p>Your study mode is designated as <strong>${escapeHtml(applicant.study_mode)}</strong>. This offer is contingent upon the verification of your original credentials during physical registration.</p>
        
        <p>Please log into your applicant dashboard to accept this offer and review your clearance guidelines.</p>
        
        <div class="footer">
          <div>Verified Digital Document</div>
          <div>Secure Ref: ${uniqueReference}</div>
        </div>
      </div>
    </body>
    </html>
  `;
}

// ---------- ADMIN ADMISSION ROUTES ----------
app.post('/api/admin/applicants/:id/generate-admission-letter', requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const applicantId = req.params.id;

    // Fetch applicant data
    const applicantResult = await client.query(
      `SELECT * FROM applicants WHERE id = $1`,
      [applicantId]
    );

    if (applicantResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Applicant record not found' });
    }

    const applicant = applicantResult.rows[0];

    if (applicant.admission_status !== 'offered' && applicant.admission_status !== 'admitted') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Cannot generate letter for applicant who is not offered/admitted.' });
    }

    // Generate HTML and compute cryptographic hash
    const htmlContent = generateAdvancedAdmissionLetterHtml(applicant);
    const documentHash = generateDocumentHash(htmlContent);

    // Save file safely to disk
    const filename = `admission-${applicant.id}-${Date.now()}.html`;
    const absolutePath = path.join(admissionUploadsDir, filename);
    const relativePath = `/uploads/private/admission/${filename}`;

    fs.writeFileSync(absolutePath, htmlContent, 'utf8');

    // Update database with path AND integrity hash (ensures schema extension or flexible update if columns exist)
    // If you prefer not to add a hash column, you can omit 'admission_hash = $2'
    await client.query(
      `UPDATE applicants 
       SET admission_letter_path = $1, updated_at = NOW() 
       WHERE id = $2`,
      [relativePath, applicantId]
    );

    await client.query('COMMIT');

    return res.status(200).json({
      success: true,
      message: 'Advanced secure admission letter generated successfully.',
      admissionLetterPath: relativePath,
      integrityHash: documentHash
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Advanced letter generation error:', err);
    return res.status(500).json({ error: 'Internal server error during letter generation.' });
  } finally {
    client.release();
  }
});

// NEW ROUTE: POST /api/admin/applicants/:id/generate-admission-letter
// Automatically builds and saves the letter using database field data
app.post(
  '/api/admin/applicants/:id/generate-admission-letter',
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      // 1. Fetch applicant details needed for the letter
      const applicantQuery = `
        SELECT 
          id, full_name, identity, program_name, program_code, 
          entry_level, study_mode, preferred_session
        FROM applicants 
        WHERE id = $1
      `;
      const applicantResult = await pool.query(applicantQuery, [id]);

      if (applicantResult.rows.length === 0) {
        return res.status(404).json({ error: 'Applicant not found' });
      }

      const applicant = applicantResult.rows[0];

      // 2. Generate the HTML string using your layout function
      const htmlContent = generateAdmissionLetterHtml(applicant);

      // 3. Save the file to disk inside uploads/private/admission
      const fileName = `admission-${applicant.identity}-${Date.now()}.html`;
      const absolutePath = path.join(admissionUploadsDir, fileName);
      const relativePath = `/uploads/private/admission/${fileName}`;

      fs.writeFileSync(absolutePath, htmlContent, 'utf8');

      // 4. Update the database record with the generated file path
      const updateResult = await pool.query(
        `UPDATE applicants
         SET
           admission_letter_path = $1,
           admission_status = COALESCE(admission_status, 'offered'),
           updated_at = NOW()
         WHERE id = $2
         RETURNING
           id,
           email,
           full_name AS "fullName",
           identity,
           admission_status AS "admissionStatus",
           admission_letter_path AS "admissionLetterPath"
        `,
        [relativePath, id]
      );

      res.json({
        message: 'Admission letter generated successfully',
        applicant: updateResult.rows[0]
      });
    } catch (err) {
      console.error('Admin generate admission letter error:', err);
      res.status(500).json({ error: 'Unable to generate admission letter' });
    }
  }
);

// ---------- HELPERS ----------

function createApplicationIdentity(id) {
  return `TFISM-APP-${String(id).padStart(6, '0')}`;
}

function uuid() {
  return `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
}

function isValidPositiveInteger(value) {
  const number = Number(value);

  return (
    Number.isInteger(number) &&
    number > 0
  );
}

// ---------- AUTH ROUTES ----------

// POST /api/login
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const {
      identity,
      role,
      password
    } = req.body;

    if (!identity || !role || !password) {
      return res.status(400).json({
        error: 'Missing credentials.'
      });
    }

    const result = await pool.query(
      `SELECT
        id,
        email,
        identity,
        role,
        password_hash,
        name
       FROM users
       WHERE (email = $1 OR identity = $1)
         AND role = $2
       LIMIT 1`,
      [identity, role]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: 'Invalid credentials.'
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: 'Invalid credentials.'
      });
    }

    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.identity = user.identity;

    res.json({
      user: {
        id: user.id,
        identity: user.identity,
        email: user.email,
        role: user.role,
        name: user.name
      }
    });
  } catch (err) {
    console.error('Login error:', err);

    res.status(500).json({
      error: 'Internal server error.'
    });
  }
});

// GET /api/me
app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Not logged in.'
    });
  }

  res.json({
    user: {
      id: req.session.userId,
      role: req.session.role,
      identity: req.session.identity
    }
  });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);

      return res.status(500).json({
        error: 'Failed to logout.'
      });
    }

    res.clearCookie(
      isProduction
        ? '__Host-tfism.sid'
        : 'tfism.sid',
      {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction
          ? 'none'
          : 'lax',
        path: '/'
      }
    );

    res.json({
      ok: true,
      message: 'Logged out successfully.'
    });
  });
});

// ---------- APPLICANT REGISTRATION ----------

// POST /api/applicants/register-step1
app.post(
  '/api/applicants/register-step1',
  async (req, res) => {
    try {
      const {
        fullName,
        email,
        sex,
        country,
        state,
        countryCode,
        phone,
        dob,
        maritalStatus,
        street,
        city,
        postalCode
      } = req.body;

      if (
        !fullName ||
        !email ||
        !sex ||
        !country ||
        !state ||
        !countryCode ||
        !phone ||
        !dob ||
        !street ||
        !city
      ) {
        return res.status(400).json({
          error: 'Missing required fields.'
        });
      }

      const normalizedEmail =
        String(email).trim().toLowerCase();

      const existingUser = await pool.query(
        `SELECT id
         FROM users
         WHERE LOWER(email) = $1
         LIMIT 1`,
        [normalizedEmail]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({
          error:
            'This email is already registered. Please login or use another email.'
        });
      }

      const existingApplicant = await pool.query(
        `SELECT id
         FROM applicants
         WHERE LOWER(email) = $1
         LIMIT 1`,
        [normalizedEmail]
      );

      if (existingApplicant.rows.length > 0) {
        return res.status(409).json({
          error:
            'An application with this email already exists. Please login to continue.'
        });
      }

      const result = await pool.query(
        `INSERT INTO applicants (
          full_name,
          email,
          sex,
          country,
          state,
          country_code,
          phone,
          dob,
          marital_status,
          street,
          city,
          postal_code,
          status
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7,
          $8, $9, $10, $11, $12, 'draft'
        )
        RETURNING id, email`,
        [
          String(fullName).trim(),
          normalizedEmail,
          sex,
          country,
          state,
          countryCode,
          phone,
          dob,
          maritalStatus || null,
          street,
          city,
          postalCode || null
        ]
      );

      const applicant = result.rows[0];

      req.session.applicationDraftId =
        applicant.id;

      res.status(201).json({
        applicant: {
          id: applicant.id,
          email: applicant.email,
          step: 1
        }
      });
    } catch (err) {
      console.error(
        'Applicant Step 1 error:',
        err
      );

      res.status(500).json({
        error: 'Internal server error.'
      });
    }
  }
);

// POST /api/applicants/register-step2
app.post(
  '/api/applicants/register-step2',
  requireApplicationDraft,
  async (req, res) => {
    try {
      const applicantId =
        req.applicantDraftId;

      const {
        nokFullName,
        nokState,
        nokCountry,
        nokCountryCode,
        nokPhone
      } = req.body;

      if (
        !nokFullName ||
        !nokState ||
        !nokCountry ||
        !nokCountryCode ||
        !nokPhone
      ) {
        return res.status(400).json({
          error: 'Missing required fields.'
        });
      }

      const check = await pool.query(
        `SELECT id, status
         FROM applicants
         WHERE id = $1
         LIMIT 1`,
        [applicantId]
      );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error: 'Application not found.'
        });
      }

      if (check.rows[0].status !== 'draft') {
        return res.status(409).json({
          error:
            'This application has already been submitted or is no longer editable.'
        });
      }

      const result = await pool.query(
        `UPDATE applicants
         SET
           nok_full_name = $1,
           nok_state = $2,
           nok_country = $3,
           nok_country_code = $4,
           nok_phone = $5,
           updated_at = NOW()
         WHERE id = $6
         RETURNING id, email`,
        [
          nokFullName,
          nokState,
          nokCountry,
          nokCountryCode,
          nokPhone,
          applicantId
        ]
      );

      res.json({
        applicant: result.rows[0],
        step: 2
      });
    } catch (err) {
      console.error(
        'Applicant Step 2 error:',
        err
      );

      res.status(500).json({
        error: 'Internal server error.'
      });
    }
  }
);

// POST /api/applicants/register-step3
app.post(
  '/api/applicants/register-step3',
  requireApplicationDraft,
  async (req, res) => {
    try {
      const applicantId =
        req.applicantDraftId;

      const {
        programCode,
        programName,
        entryLevel,
        studyMode,
        preferredSession,
        preferredSemester,
        password
      } = req.body;

      if (
        !programCode ||
        !programName ||
        !entryLevel ||
        !studyMode ||
        !password
      ) {
        return res.status(400).json({
          error: 'Missing required fields.'
        });
      }

      if (String(password).length < 8) {
        return res.status(400).json({
          error: 'Password must be at least 8 characters.'
        });
      }

      const check = await pool.query(
        `SELECT id, status
         FROM applicants
         WHERE id = $1
         LIMIT 1`,
        [applicantId]
      );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error: 'Application not found.'
        });
      }

      if (check.rows[0].status !== 'draft') {
        return res.status(409).json({
          error:
            'This application has already been submitted or is no longer editable.'
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = await pool.query(
        `UPDATE applicants
         SET
           program_code = $1,
           program_name = $2,
           entry_level = $3,
           study_mode = $4,
           preferred_session = $5,
           preferred_semester = $6,
           password_hash = $7,
           updated_at = NOW()
         WHERE id = $8
         RETURNING id, email`,
        [
          programCode,
          programName,
          entryLevel,
          studyMode,
          preferredSession || null,
          preferredSemester || null,
          passwordHash,
          applicantId
        ]
      );

      res.json({
        applicant: result.rows[0],
        step: 3
      });
    } catch (err) {
      console.error(
        'Applicant Step 3 error:',
        err
      );

      res.status(500).json({
        error: 'Internal server error.'
      });
    }
  }
);

// POST /api/applicants/register-step4
app.post(
  '/api/applicants/register-step4',
  requireApplicationDraft,
  upload.fields([
    { name: 'waecFile', maxCount: 1 },
    { name: 'necoFile', maxCount: 1 },
    { name: 'birthCertFile', maxCount: 1 },
    { name: 'passportFile', maxCount: 1 },
    { name: 'transcriptFile', maxCount: 1 },
    { name: 'otherFile', maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const applicantId =
        req.applicantDraftId;

      const check = await pool.query(
        `SELECT id, status
         FROM applicants
         WHERE id = $1
         LIMIT 1`,
        [applicantId]
      );

      if (check.rows.length === 0) {
        deleteUploadedFiles(
          Object.values(req.files || {}).flat()
        );

        return res.status(404).json({
          error: 'Application not found.'
        });
      }

      if (check.rows[0].status !== 'draft') {
        deleteUploadedFiles(
          Object.values(req.files || {}).flat()
        );

        return res.status(409).json({
          error:
            'This application has already been submitted or is no longer editable.'
        });
      }

      const files = req.files || {};

      const getFile = (field) => {
        return files[field]?.[0] || null;
      };

      const waecFile = getFile('waecFile');
      const necoFile = getFile('necoFile');
      const birthCertFile = getFile('birthCertFile');
      const passportFile = getFile('passportFile');
      const transcriptFile = getFile('transcriptFile');
      const otherFile = getFile('otherFile');

      if (!waecFile || !birthCertFile || !passportFile) {
        deleteUploadedFiles(
          Object.values(files).flat()
        );

        return res.status(400).json({
          error:
            'Missing required files (WAEC, Birth Certificate, Passport Photo).'
        });
      }

      const filePath = (file) => {
        return file
          ? `/api/applicants/files/${file.filename}`
          : null;
      };

      const result = await pool.query(
        `UPDATE applicants
         SET
           waec_file_path = $1,
           neco_file_path = $2,
           birth_cert_file_path = $3,
           passport_file_path = $4,
           transcript_file_path = $5,
           other_file_path = $6,
           updated_at = NOW()
         WHERE id = $7
         RETURNING id, email`,
        [
          filePath(waecFile),
          filePath(necoFile),
          filePath(birthCertFile),
          filePath(passportFile),
          filePath(transcriptFile),
          filePath(otherFile),
          applicantId
        ]
      );

      res.json({
        applicant: result.rows[0],
        step: 4
      });
    } catch (err) {
      deleteUploadedFiles(
        Object.values(req.files || {}).flat()
      );

      console.error(
        'Applicant Step 4 error:',
        err
      );

      res.status(500).json({
        error: 'Internal server error.'
      });
    }
  }
);

// GET /api/applicants/draft
app.get(
  '/api/applicants/draft',
  requireApplicationDraft,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
          id,
          email,
          full_name AS "fullName",
          sex,
          country,
          state,
          country_code AS "countryCode",
          phone,
          dob,
          marital_status AS "maritalStatus",
          street,
          city,
          postal_code AS "postalCode",
          nok_full_name AS "nokFullName",
          nok_state AS "nokState",
          nok_country AS "nokCountry",
          nok_country_code AS "nokCountryCode",
          nok_phone AS "nokPhone",
          program_code AS "programCode",
          program_name AS "programName",
          entry_level AS "entryLevel",
          study_mode AS "studyMode",
          preferred_session AS "preferredSession",
          preferred_semester AS "preferredSemester",
          waec_file_path AS "waecFilePath",
          neco_file_path AS "necoFilePath",
          birth_cert_file_path AS "birthCertFilePath",
          passport_file_path AS "passportFilePath",
          transcript_file_path AS "transcriptFilePath",
          other_file_path AS "otherFilePath",
          identity,
          role,
          status
         FROM applicants
         WHERE id = $1
         LIMIT 1`,
        [req.applicantDraftId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Application draft not found.'
        });
      }

      res.json({
        applicant: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Load application draft error:',
        err
      );

      res.status(500).json({
        error: 'Unable to load application draft.'
      });
    }
  }
);
// ---------- FINALIZE APPLICATION ----------

// POST /api/applicants/finalize
app.post(
  '/api/applicants/finalize',
  requireApplicationDraft,
  async (req, res) => {
    let client;

    try {
      client = await pool.connect();

      const { confirmed } = req.body;

      if (confirmed !== true) {
        return res.status(400).json({
          error:
            'You must confirm that your application details are correct.'
        });
      }

      await client.query('BEGIN');

      const applicationResult = await client.query(
        `SELECT
          id,
          email,
          full_name,
          password_hash,
          status,
          identity,
          role,
          nok_full_name,
          nok_state,
          nok_country,
          nok_country_code,
          nok_phone,
          program_code,
          program_name,
          entry_level,
          study_mode,
          preferred_session,
          preferred_semester,
          waec_file_path,
          birth_cert_file_path,
          passport_file_path
         FROM applicants
         WHERE id = $1
         FOR UPDATE`,
        [req.applicantDraftId]
      );

      if (applicationResult.rows.length === 0) {
        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Application draft not found.'
        });
      }

      const application =
        applicationResult.rows[0];

      if (application.status !== 'draft') {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error:
            'This application has already been submitted or is no longer editable.'
        });
      }

      const missingFields = [];

      if (!application.password_hash) {
        missingFields.push('account password');
      }

      if (!application.nok_full_name) {
        missingFields.push('next-of-kin name');
      }

      if (!application.nok_state) {
        missingFields.push('next-of-kin state');
      }

      if (!application.nok_country) {
        missingFields.push('next-of-kin country');
      }

      if (!application.nok_country_code) {
        missingFields.push('next-of-kin country code');
      }

      if (!application.nok_phone) {
        missingFields.push('next-of-kin phone number');
      }

      if (!application.program_code) {
        missingFields.push('program');
      }

      if (!application.program_name) {
        missingFields.push('program name');
      }

      if (!application.entry_level) {
        missingFields.push('entry level');
      }

      if (!application.study_mode) {
        missingFields.push('study mode');
      }

      if (!application.waec_file_path) {
        missingFields.push('WAEC/SSCE certificate');
      }

      if (!application.birth_cert_file_path) {
        missingFields.push('birth certificate');
      }

      if (!application.passport_file_path) {
        missingFields.push('passport photograph');
      }

      if (missingFields.length > 0) {
        await client.query('ROLLBACK');

        return res.status(400).json({
          error:
            `Complete the following before submission: ` +
            `${missingFields.join(', ')}.`
        });
      }

      const duplicateUser = await client.query(
        `SELECT id
         FROM users
         WHERE LOWER(email) = LOWER($1)
         LIMIT 1`,
        [application.email]
      );

      if (duplicateUser.rows.length > 0) {
        await client.query('ROLLBACK');

        return res.status(409).json({
          error:
            'An account already exists for this email address. Please contact support.'
        });
      }

      const applicationIdentity =
        application.identity ||
        createApplicationIdentity(application.id);

      await client.query(
        `UPDATE applicants
         SET
           identity = $1,
           role = 'applicant',
           status = 'submitted',
           updated_at = NOW()
         WHERE id = $2`,
        [
          applicationIdentity,
          application.id
        ]
      );

      const userResult = await client.query(
        `INSERT INTO users (
          email,
          identity,
          role,
          password_hash,
          name
        )
        VALUES (
          $1,
          $2,
          'applicant',
          $3,
          $4
        )
        RETURNING id, email, identity, role, name`,
        [
          application.email,
          applicationIdentity,
          application.password_hash,
          application.full_name
        ]
      );

      await client.query('COMMIT');

      const user = userResult.rows[0];

      delete req.session.applicationDraftId;

      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.identity = user.identity;

      return res.json({
        message: 'Application submitted successfully.',
        applicant: {
          id: application.id,
          identity: applicationIdentity,
          status: 'submitted'
        },
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          identity: user.identity,
          role: user.role
        }
      });
    } catch (err) {
      if (client) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          console.error(
            'Finalize rollback error:',
            rollbackError.message
          );
        }
      }

      console.error(
        'Finalize application error:',
        err
      );

      return res.status(500).json({
        error:
          'Unable to submit application. Please try again.'
      });
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);

// ---------- APPLICANT DASHBOARD ----------

// GET /api/applicants/me
app.get(
  '/api/applicants/me',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const result = await pool.query(
        `SELECT
          a.id,
          a.email,
          a.full_name AS "fullName",
          a.sex,
          a.country,
          a.state,
          a.country_code AS "countryCode",
          a.phone,
          a.dob,
          a.marital_status AS "maritalStatus",
          a.street,
          a.city,
          a.postal_code AS "postalCode",
          a.nok_full_name AS "nokFullName",
          a.nok_state AS "nokState",
          a.nok_country AS "nokCountry",
          a.nok_country_code AS "nokCountryCode",
          a.nok_phone AS "nokPhone",
          a.program_code AS "programCode",
          a.program_name AS "programName",
          a.entry_level AS "entryLevel",
          a.study_mode AS "studyMode",
          a.preferred_session AS "preferredSession",
          a.preferred_semester AS "preferredSemester",
          a.waec_file_path AS "waecFilePath",
          a.neco_file_path AS "necoFilePath",
          a.birth_cert_file_path AS "birthCertFilePath",
          a.passport_file_path AS "passportFilePath",
          a.transcript_file_path AS "transcriptFilePath",
          a.other_file_path AS "otherFilePath",
          a.identity,
          a.role,
          a.status,
          a.payment_status AS "paymentStatus",
          a.payment_reference AS "paymentReference",
          a.payment_amount AS "paymentAmount",
          a.payment_currency AS "paymentCurrency",
          a.payment_paid_at AS "paymentPaidAt"
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant record not found.'
        });
      }

      res.json({
        applicant: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Error fetching applicant profile:',
        err
      );

      res.status(500).json({
        error: 'Failed to fetch profile.'
      });
    }
  }
);

// PATCH /api/applicants/profile
app.patch(
  '/api/applicants/profile',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const {
        fullName,
        phone,
        dob,
        address
      } = req.body;

      const updates = [];
      const values = [];

      if (fullName !== undefined) {
        updates.push(
          `full_name = $${values.length + 1}`
        );
        values.push(String(fullName).trim());
      }

      if (phone !== undefined) {
        updates.push(
          `phone = $${values.length + 1}`
        );
        values.push(String(phone).trim());
      }

      if (dob !== undefined) {
        updates.push(
          `dob = $${values.length + 1}`
        );
        values.push(dob);
      }

      if (address !== undefined) {
        updates.push(
          `street = $${values.length + 1}`
        );
        values.push(String(address).trim());
      }

      if (updates.length === 0) {
        return res.status(400).json({
          error: 'No fields to update.'
        });
      }

      updates.push('updated_at = NOW()');

      values.push(userId);

      const userIdPlaceholder =
        `$${values.length}`;

      const updateResult = await pool.query(
        `UPDATE applicants
         SET ${updates.join(', ')}
         WHERE email = (
           SELECT email
           FROM users
           WHERE id = ${userIdPlaceholder}
         )
         RETURNING
           id,
           email,
           full_name AS "fullName",
           phone,
           dob,
           street,
           city,
           state,
           country,
           postal_code AS "postalCode",
           passport_file_path AS "passportFilePath",
           program_code AS "programCode",
           program_name AS "programName",
           entry_level AS "entryLevel",
           study_mode AS "studyMode",
           preferred_session AS "preferredSession",
           status`,
        values
      );

      if (updateResult.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant record not found.'
        });
      }

      res.json({
        applicant: updateResult.rows[0]
      });
    } catch (err) {
      console.error(
        'Error updating profile:',
        err
      );

      res.status(500).json({
        error: 'Failed to update profile.'
      });
    }
  }
);

// POST /api/applicants/avatar
app.post(
  '/api/applicants/avatar',
  requireApplicantAuth,
  upload.single('passportFile'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'No file uploaded.'
        });
      }

      const filePath =
        `/api/applicants/files/${req.file.filename}`;

      const userId = req.session.userId;

      const updateResult = await pool.query(
        `UPDATE applicants
         SET
           passport_file_path = $1,
           updated_at = NOW()
         WHERE email = (
           SELECT email
           FROM users
           WHERE id = $2
         )`,
        [
          filePath,
          userId
        ]
      );

      if (updateResult.rowCount === 0) {
        return res.status(404).json({
          error: 'Applicant record not found.'
        });
      }

      const result = await pool.query(
        `SELECT
          a.id,
          a.email,
          a.full_name AS "fullName",
          a.passport_file_path AS "passportFilePath"
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      res.json({
        applicant: result.rows[0]
      });
    } catch (err) {
      if (req.file) {
        deleteUploadedFiles([req.file]);
      }

      console.error(
        'Error updating avatar:',
        err
      );

      res.status(500).json({
        error: 'Failed to update avatar.'
      });
    }
  }
);

// POST /api/applicants/change-password
app.post(
  '/api/applicants/change-password',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const {
        currentPassword,
        newPassword
      } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          error:
            'Current and new password are required.'
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          error:
            'New password must be at least 8 characters.'
        });
      }

      const result = await pool.query(
        `SELECT a.password_hash
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant not found.'
        });
      }

      const applicant = result.rows[0];

      const valid = await bcrypt.compare(
        currentPassword,
        applicant.password_hash
      );

      if (!valid) {
        return res.status(400).json({
          error: 'Current password is incorrect.'
        });
      }

      const newHash = await bcrypt.hash(
        newPassword,
        12
      );

      await pool.query(
        `UPDATE applicants
         SET
           password_hash = $1,
           updated_at = NOW()
         WHERE email = (
           SELECT email
           FROM users
           WHERE id = $2
         )`,
        [
          newHash,
          userId
        ]
      );

      await pool.query(
        `UPDATE users
         SET
           password_hash = $1
         WHERE id = $2`,
        [
          newHash,
          userId
        ]
      );

      res.json({
        message: 'Password changed successfully.'
      });
    } catch (err) {
      console.error(
        'Error changing password:',
        err
      );

      res.status(500).json({
        error: 'Failed to change password.'
      });
    }
  }
);

// POST /api/applicants/logout
app.post(
  '/api/applicants/logout',
  (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error(
          'Error destroying session:',
          err
        );

        return res.status(500).json({
          error: 'Failed to logout.'
        });
      }

      res.clearCookie(
        isProduction
          ? '__Host-tfism.sid'
          : 'tfism.sid',
        {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction
            ? 'none'
            : 'lax',
          path: '/'
        }
      );

      res.json({
        message: 'Logged out successfully.'
      });
    });
  }
);

// ---------- PRIVATE FILE ACCESS ----------

app.get(
  '/api/applicants/files/:filename',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const filename =
        path.basename(req.params.filename);

      const result = await pool.query(
        `SELECT
          a.passport_file_path,
          a.waec_file_path,
          a.neco_file_path,
          a.birth_cert_file_path,
          a.transcript_file_path,
          a.other_file_path,
          a.admission_letter_path
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [req.session.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant not found.'
        });
      }

      const allowedFilenames = Object
        .values(result.rows[0])
        .filter(Boolean)
        .map((filePath) => path.basename(filePath));

      if (!allowedFilenames.includes(filename)) {
        return res.status(403).json({
          error: 'You are not allowed to access this file.'
        });
      }

      const absolutePath = path.join(
        privateUploadsDir,
        filename
      );

      if (!fs.existsSync(absolutePath)) {
        return res.status(404).json({
          error: 'File not found.'
        });
      }

      res.sendFile(absolutePath);
    } catch (err) {
      console.error(
        'Private file error:',
        err
      );

      res.status(500).json({
        error: 'Unable to retrieve file.'
      });
    }
  }
);

// ---------- PAYMENT CONFIGURATION ----------

const PAYSTACK_SECRET =
  process.env.PAYSTACK_SECRET_KEY;

const PAYSTACK_BASE =
  'https://api.paystack.co';

const FEE_AMOUNT =
  Number(process.env.APPLICATION_FEE_AMOUNT) || 5000;

const FEE_CURRENCY =
  process.env.APPLICATION_FEE_CURRENCY || 'NGN';

// POST /api/payments/initiate
app.post(
  '/api/payments/initiate',
  requireApplicantAuth,
  async (req, res) => {
    try {
      if (!PAYSTACK_SECRET) {
        return res.status(503).json({
          error:
            'Payment service is not configured.'
        });
      }

      const userId = req.session.userId;

      const applicantResult = await pool.query(
        `SELECT
          a.id,
          a.email,
          a.full_name,
          a.payment_status
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      if (applicantResult.rows.length === 0) {
        return res.status(404).json({
          error: 'No applicant record found.'
        });
      }

      const applicant =
        applicantResult.rows[0];

      if (applicant.payment_status === 'paid') {
        return res.status(409).json({
          error: 'Application fee already paid.',
          alreadyPaid: true
        });
      }

      const reference = uuid();

      const paymentResult = await pool.query(
        `INSERT INTO payments (
          applicant_id,
          user_id,
          amount,
          currency,
          reference,
          provider,
          status
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'pending')
        RETURNING id, reference`,
        [
          applicant.id,
          userId,
          FEE_AMOUNT,
          FEE_CURRENCY,
          reference,
          'paystack'
        ]
      );

      const payment =
        paymentResult.rows[0];

      const paystackRes = await axios.post(
        `${PAYSTACK_BASE}/transaction/initialize`,
        {
          email: applicant.email,
          amount: FEE_AMOUNT * 100,
          currency: FEE_CURRENCY,
          reference,
          metadata: {
            applicant_id: applicant.id,
            payment_id: payment.id
          }
        },
        {
          headers: {
            Authorization:
              `Bearer ${PAYSTACK_SECRET}`,
            'Content-Type':
              'application/json'
          },
          timeout: 15000
        }
      );

      const data = paystackRes.data;

      if (
        !data ||
        !data.status ||
        !data.data ||
        !data.data.authorization_url
      ) {
        throw new Error(
          'Invalid response from payment provider.'
        );
      }

      res.json({
        authorization_url:
          data.data.authorization_url,
        reference,
        amount: FEE_AMOUNT,
        currency: FEE_CURRENCY
      });
    } catch (err) {
      console.error(
        'Payment initialization error:',
        err
      );

      res.status(500).json({
        error:
          err.response?.data?.message ||
          'Unable to initiate payment.'
      });
    }
  }
);

// GET /api/payments/verify/:reference
app.get(
  '/api/payments/verify/:reference',
  requireApplicantAuth,
  async (req, res) => {
    try {
      if (!PAYSTACK_SECRET) {
        return res.status(503).json({
          error:
            'Payment service is not configured.'
        });
      }

      const reference = String(
        req.params.reference || ''
      ).trim();

      if (!reference) {
        return res.status(400).json({
          error: 'Missing reference.'
        });
      }

      const paymentResult = await pool.query(
        `SELECT
          id,
          applicant_id,
          user_id,
          status,
          reference
         FROM payments
         WHERE reference = $1
         LIMIT 1`,
        [reference]
      );

      if (paymentResult.rows.length === 0) {
        return res.status(404).json({
          error: 'Payment record not found.'
        });
      }

      const payment =
        paymentResult.rows[0];

      if (
        payment.user_id !== req.session.userId
      ) {
        return res.status(403).json({
          error: 'You cannot verify this payment.'
        });
      }

      const paystackRes = await axios.get(
        `${PAYSTACK_BASE}/transaction/verify/${encodeURIComponent(reference)}`,
        {
          headers: {
            Authorization:
              `Bearer ${PAYSTACK_SECRET}`
          },
          timeout: 15000
        }
      );

      const data = paystackRes.data;

      if (!data || !data.status || !data.data) {
        return res.status(502).json({
          error:
            'Invalid response from payment provider.'
        });
      }

      const tx = data.data;
      const status = tx.status;
      const paidAt = tx.paid_at
        ? new Date(tx.paid_at).toISOString()
        : null;

      if (status === 'success') {
        await pool.query(
          `UPDATE payments
           SET
             status = 'success',
             provider_reference = $1,
             metadata = $2,
             updated_at = NOW()
           WHERE id = $3`,
          [
            tx.reference,
            JSON.stringify(tx),
            payment.id
          ]
        );

        await pool.query(
          `UPDATE applicants
           SET
             payment_status = 'paid',
             payment_reference = $1,
             payment_amount = $2,
             payment_currency = $3,
             payment_paid_at = $4,
             updated_at = NOW()
           WHERE id = $5
             AND (
               payment_status IS NULL
               OR payment_status <> 'paid'
             )`,
          [
            reference,
            FEE_AMOUNT,
            FEE_CURRENCY,
            paidAt,
            payment.applicant_id
          ]
        );
      } else if (
        status === 'failed' ||
        status === 'abandoned'
      ) {
        await pool.query(
          `UPDATE payments
           SET
             status = 'failed',
             provider_reference = $1,
             metadata = $2,
             updated_at = NOW()
           WHERE id = $3`,
          [
            tx.reference,
            JSON.stringify(tx),
            payment.id
          ]
        );
      }

      res.json({
        reference,
        status,
        amount: tx.amount / 100,
        currency: tx.currency,
        paid_at: paidAt,
        payment: {
          id: payment.id,
          applicant_id: payment.applicant_id
        }
      });
    } catch (err) {
      console.error(
        'Payment verification error:',
        err
      );

      res.status(500).json({
        error:
          err.response?.data?.message ||
          'Unable to verify payment.'
      });
    }
  }
);

// GET /api/payments/status
app.get(
  '/api/payments/status',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const result = await pool.query(
        `SELECT
          a.id AS applicant_id,
          a.payment_status,
          a.payment_reference,
          a.payment_amount,
          a.payment_currency,
          a.payment_paid_at,
          p.reference AS last_payment_reference,
          p.status AS last_payment_status
         FROM applicants a
         JOIN users u ON u.email = a.email
         LEFT JOIN payments p
           ON p.applicant_id = a.id
         WHERE u.id = $1
         ORDER BY p.created_at DESC NULLS LAST
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'No applicant record found.'
        });
      }

      const row = result.rows[0];

      res.json({
        applicant_id: row.applicant_id,
        payment_status:
          row.payment_status || 'unpaid',
        payment_reference:
          row.payment_reference,
        payment_amount:
          row.payment_amount,
        payment_currency:
          row.payment_currency,
        payment_paid_at:
          row.payment_paid_at,
        last_payment_reference:
          row.last_payment_reference,
        last_payment_status:
          row.last_payment_status
      });
    } catch (err) {
      console.error(
        'Payment status error:',
        err
      );

      res.status(500).json({
        error: 'Unable to fetch payment status.'
      });
    }
  }
);

// ---------- ADMIN ROUTES ----------

// GET /api/admin/applicants
app.get(
  '/api/admin/applicants',
  requireAdmin,
  async (req, res) => {
    try {
      const {
        status,
        payment_status,
        search,
        page = '1',
        limit = '20'
      } = req.query;

      const pageNum = Math.max(
        1,
        parseInt(page, 10) || 1
      );

      const limitNum = Math.min(
        100,
        Math.max(1, parseInt(limit, 10) || 20)
      );

      const offset =
        (pageNum - 1) * limitNum;

      const conditions = [];
      const values = [];

      if (status) {
        values.push(status);

        conditions.push(
          `a.status = $${values.length}`
        );
      }

      if (payment_status) {
        values.push(payment_status);

        conditions.push(
          `a.payment_status = $${values.length}`
        );
      }

      if (search) {
        values.push(`%${search}%`);

        conditions.push(
          `(a.full_name ILIKE $${values.length}
            OR a.email ILIKE $${values.length}
            OR a.identity ILIKE $${values.length})`
        );
      }

      const whereClause =
        conditions.length > 0
          ? `WHERE ${conditions.join(' AND ')}`
          : '';

      const countQuery = `
        SELECT COUNT(*) AS total
        FROM applicants a
        ${whereClause}
      `;

      const countResult = await pool.query(
        countQuery,
        values
      );

      const total = parseInt(
        countResult.rows[0].total,
        10
      ) || 0;

      const dataQuery = `
        SELECT
          a.id,
          a.email,
          a.full_name,
          a.identity,
          a.status,
          a.payment_status,
          a.payment_amount,
          a.payment_currency,
          a.payment_paid_at,
          a.program_code,
          a.program_name,
          a.entry_level,
          a.study_mode,
          a.created_at
        FROM applicants a
        ${whereClause}
        ORDER BY a.created_at DESC
        LIMIT $${values.length + 1}
        OFFSET $${values.length + 2}
      `;

      const dataValues = [
        ...values,
        limitNum,
        offset
      ];

      const dataResult = await pool.query(
        dataQuery,
        dataValues
      );

      res.json({
        total,
        page: pageNum,
        limit: limitNum,
        applicants: dataResult.rows
      });
    } catch (err) {
      console.error(
        'Admin list applicants error:',
        err
      );

      res.status(500).json({
        error: 'Unable to list applicants.'
      });
    }
  }
);

// GET /api/admin/applicants/:id
app.get(
  '/api/admin/applicants/:id',
  requireAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!isValidPositiveInteger(id)) {
        return res.status(400).json({
          error: 'Invalid applicant ID.'
        });
      }

      const result = await pool.query(
        `SELECT
          a.*,
          u.id AS user_id,
          u.identity AS user_identity,
          u.role AS user_role
         FROM applicants a
         LEFT JOIN users u
           ON u.email = a.email
         WHERE a.id = $1
         LIMIT 1`,
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant not found.'
        });
      }

      res.json({
        applicant: result.rows[0]
      });
    } catch (err) {
      console.error(
        'Admin get applicant error:',
        err
      );

      res.status(500).json({
        error: 'Unable to fetch applicant details.'
      });
    }
  }
);

// GET /api/applicants/admission-letter
app.get(
  '/api/applicants/admission-letter',
  requireApplicantAuth,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const result = await pool.query(
        `SELECT
          a.id,
          a.full_name AS "fullName",
          a.identity,
          a.program_name AS "programName",
          a.program_code AS "programCode",
          a.entry_level AS "entryLevel",
          a.study_mode AS "studyMode",
          a.preferred_session AS "preferredSession",
          a.status,
          a.admission_status AS "admissionStatus",
          a.admission_letter_path AS "admissionLetterPath"
         FROM applicants a
         JOIN users u ON u.email = a.email
         WHERE u.id = $1
         LIMIT 1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: 'Applicant not found.'
        });
      }

      const applicant = result.rows[0];

      const canDownload =
        (
          applicant.admissionStatus === 'offered' ||
          applicant.admissionStatus === 'admitted'
        ) &&
        applicant.admissionLetterPath;

      res.json({
        applicant: {
          fullName: applicant.fullName,
          identity: applicant.identity,
          programName: applicant.programName,
          programCode: applicant.programCode,
          entryLevel: applicant.entryLevel,
          studyMode: applicant.studyMode,
          preferredSession:
            applicant.preferredSession,
          status: applicant.status,
          admissionStatus:
            applicant.admissionStatus
        },

        admissionLetter: canDownload
          ? {
              url: applicant.admissionLetterPath,
              fileName:
                `Admission-Letter-${applicant.identity}.html`
            }
          : null
      });
    } catch (err) {
      console.error(
        'Admission letter error:',
        err
      );

      res.status(500).json({
        error:
          'Unable to fetch admission letter information.'
      });
    }
  }
);

// ---------- ERROR HANDLERS ----------

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: `Upload error: ${err.message}`
    });
  }

  if (err.message) {
    return res.status(400).json({
      error: err.message
    });
  }

  res.status(500).json({
    error: 'Internal server error.'
  });
});

// ==========================================
// APPLICANT ROUTE: Accept Admission Offer
// ==========================================
app.post('/api/applicant/accept-offer', requireApplicant, async (req, res) => {
  try {
    const applicantId = req.user.id;

    // Fetch current status
    const checkQuery = `SELECT admission_status FROM applicants WHERE id = $1`;
    const checkResult = await pool.query(checkQuery, [applicantId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Applicant record not found.' });
    }

    const { admission_status } = checkResult.rows[0];

    // Verify they have a valid offer to accept
    if (admission_status !== 'offered') {
      return res.status(400).json({ 
        error: `Cannot accept offer. Current admission status is '${admission_status}'.` 
      });
    }

    // Update status to 'accepted'
    const updateQuery = `
      UPDATE applicants
      SET admission_status = 'accepted', updated_at = NOW()
      WHERE id = $1
      RETURNING id, full_name AS "fullName", admission_status AS "admissionStatus", updated_at AS "updatedAt"
    `;
    const updateResult = await pool.query(updateQuery, [applicantId]);

    console.log(`[AUDIT] Applicant ID ${applicantId} formally accepted their admission offer.`);

    return res.json({
      message: 'Admission offer accepted successfully!',
      applicant: updateResult.rows[0]
    });

  } catch (err) {
    console.error('Accept admission offer error:', err);
    return res.status(500).json({ error: 'Unable to process offer acceptance due to an internal server error.' });
  }
});

// ==========================================
// APPLICANT ROUTE: Submit Application (Gated by Application Fee)
// ==========================================
app.post('/api/applicant/submit', requireApplicant, async (req, res) => {
  try {
    const applicantId = req.user.id;

    // 1. Check current applicant status and fee payment status
    const applicantQuery = `
      SELECT id, application_status, app_fee_paid, fee_status 
      FROM applicants 
      WHERE id = $1
    `;
    const result = await pool.query(applicantQuery, [applicantId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Applicant record not found.' });
    }

    const applicant = result.rows[0];

    // Prevent re-submission if already submitted
    if (applicant.application_status && applicant.application_status !== 'draft') {
      return res.status(400).json({ error: 'Application has already been submitted.' });
    }

    // STRICT GATE: Ensure application fee is paid/cleared
    // (Assuming you have a boolean column 'app_fee_paid' or text 'fee_status' === 'paid')
    if (!applicant.app_fee_paid && applicant.fee_status !== 'paid' && applicant.fee_status !== 'cleared') {
      return res.status(402).json({ 
        error: 'Payment Required: You must pay the application fee before you can submit your application.' 
      });
    }

    // 2. Update status to submitted
    const updateQuery = `
      UPDATE applicants
      SET 
        application_status = 'submitted',
        submitted_at = NOW(),
        updated_at = NOW()
      WHERE id = $1
      RETURNING id, full_name AS "fullName", application_status AS "applicationStatus"
    `;
    const updateResult = await pool.query(updateQuery, [applicantId]);

    console.log(`[AUDIT] Applicant ID ${applicantId} successfully submitted their application after fee verification.`);

    return res.json({
      message: 'Application submitted successfully!',
      applicant: updateResult.rows[0]
    });

  } catch (err) {
    console.error('Submit application error:', err);
    return res.status(500).json({ error: 'Unable to submit application due to an internal server error.' });
  }
});

// ==========================================
// APPLICANT ROUTE: View/Download Admission Letter (Payment & Status Gated)
// ==========================================
app.get('/api/applicant/admission-letter', requireApplicant, async (req, res) => {
  try {
    const applicantId = req.user.id; 

    // Fetch applicant record, admission status, and fee clearance status
    const result = await pool.query(
      `SELECT id, full_name, admission_letter_path, admission_status, acceptance_fee_paid, fee_status 
       FROM applicants WHERE id = $1`,
      [applicantId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Applicant record not found' });
    }

    const applicant = result.rows[0];

    // 1. Strict admission status validation
    if (applicant.admission_status !== 'offered' && applicant.admission_status !== 'admitted') {
      return res.status(403).json({ 
        error: 'Admission letter is not yet available or your admission offer has not been extended.' 
      });
    }

    // 2. STRICT PAYMENT GATE: Ensure acceptance/clearance fee is paid before letter access
    // Adjust 'acceptance_fee_paid' or 'fee_status' based on your actual database schema column names
    const hasPaidAcceptanceFee = applicant.acceptance_fee_paid === true || applicant.fee_status === 'cleared' || applicant.fee_status === 'paid';
    
    if (!hasPaidAcceptanceFee) {
      return res.status(402).json({ 
        error: 'Payment Required: You must pay your acceptance fee before you can view or download your admission letter.' 
      });
    }

    if (!applicant.admission_letter_path) {
      return res.status(404).json({ error: 'Admission letter file has not been generated by admin yet.' });
    }

    // Convert stored relative path into an absolute file path safely
    const absolutePath = path.join(__dirname, applicant.admission_letter_path);

    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({ error: 'Letter file missing from server storage.' });
    }

    // Stream file securely to client browser
    return res.sendFile(absolutePath);

  } catch (err) {
    console.error('Applicant fetch admission letter error:', err);
    return res.status(500).json({ error: 'Unable to retrieve admission letter due to an internal server error.' });
  }
});

// ==========================================
// PAYMENT WEBHOOK: Automatically Update Payment Status
// ==========================================
app.post('/api/payments/webhook', async (req, res) => {
  try {
    // 1. (Recommended) Verify signature from your payment provider header 
    // e.g., Paystack uses req.headers['x-paystack-signature'] verified via crypto HMAC
    const event = req.body;

    // Check if the event is a successful charge/payment
    // Structure typically matches Paystack: event.event === 'charge.success'
    // Or Flutterwave: event.event === 'successful-payment'
    if (event && (event.event === 'charge.success' || event.event === 'successful-payment')) {
      const data = event.data;
      
      // Extract metadata or customer email/reference passed during payment initialization
      // Assuming you passed applicantId inside metadata: metadata: { applicantId: 123, paymentType: 'application_fee' }
      const applicantId = data.metadata?.applicantId || data.customer?.metadata?.applicantId;
      const paymentType = data.metadata?.paymentType; // 'application_fee' or 'acceptance_fee'

      if (!applicantId) {
        console.warn('Webhook received successful charge, but no applicantId found in metadata.');
        return res.status(200).json({ received: true }); // Return 200 so the gateway stops retrying
      }

      // 2. Conditionally update the correct boolean column based on paymentType
      if (paymentType === 'application_fee') {
        await pool.query(
          `UPDATE applicants 
           SET app_fee_paid = TRUE, fee_status = 'paid', updated_at = NOW() 
           WHERE id = $1`,
          [applicantId]
        );
        console.log(`[WEBHOOK] Application fee marked as PAID for applicant ID ${applicantId}`);
      } else if (paymentType === 'acceptance_fee') {
        await pool.query(
          `UPDATE applicants 
           SET acceptance_fee_paid = TRUE, fee_status = 'cleared', updated_at = NOW() 
           WHERE id = $1`,
          [applicantId]
        );
        console.log(`[WEBHOOK] Acceptance fee marked as PAID for applicant ID ${applicantId}`);
      }
    }

    // Always respond with 200 OK quickly to acknowledge receipt to the payment provider
    return res.status(200).json({ received: true });

  } catch (err) {
    console.error('Payment webhook error:', err);
    return res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ==========================================
// APPLICANT ROUTE: Get Portal Dashboard Summary
// ==========================================
app.get('/api/applicant/Applicant', requireApplicant, async (req, res) => {
  try {
    const applicantId = req.user.id;

    const query = `
      SELECT 
        id,
        full_name AS "fullName",
        email,
        identity,
        phone,
        dob,
        street,
        program_name AS "programName",
        program_code AS "programCode",
        entry_level AS "entryLevel",
        study_mode AS "studyMode",
        preferred_session AS "preferredSession",
        passport_file_path AS "passportFilePath",
        status,
        application_status AS "applicationStatus",
        admission_status AS "admissionStatus",
        payment_status AS "paymentStatus",
        payment_amount AS "paymentAmount",
        created_at AS "createdAt",
        updated_at AS "updatedAt"
      FROM applicants 
      WHERE id = $1
    `;

    const result = await pool.query(query, [applicantId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Applicant record not found.' });
    }

    const applicant = result.rows[0];

    // Compute permission flags based on your schema default values
    const canSubmitApplication = (applicant.applicationStatus || applicant.status) === 'draft' && applicant.paymentStatus === 'paid';
    const canAcceptOffer = applicant.admissionStatus === 'offered';
    const canDownloadLetter = applicant.admissionStatus === 'offered' || applicant.admissionStatus === 'admitted';

    return res.json({
      success: true,
      applicant: {
        ...applicant,
        permissions: {
          canSubmitApplication,
          canAcceptOffer,
          canDownloadLetter
        }
      }
    });
  } catch (err) {
    console.error('Error fetching applicant dashboard data:', err);
    return res.status(500).json({ error: 'Internal server error loading dashboard.' });
  }
});

// ---------- START SERVER ----------

app.listen(PORT, () => {
  console.log(
    `API running on http://localhost:${PORT}`
  );
});