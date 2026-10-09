-- Users
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  identity TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL, -- applicant, student, staff, hod, admin
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Applicants
CREATE TABLE IF NOT EXISTS applicants (
  id SERIAL PRIMARY KEY,

  -- Biodata
  email TEXT NOT NULL,
  full_name TEXT NOT NULL,
  sex TEXT NOT NULL,
  country TEXT NOT NULL,
  state TEXT NOT NULL,
  country_code TEXT NOT NULL,
  phone TEXT NOT NULL,
  dob DATE NOT NULL,
  marital_status TEXT,
  street TEXT NOT NULL,
  city TEXT NOT NULL,
  postal_code TEXT,

  -- Next of kin
  nok_full_name TEXT,
  nok_state TEXT,
  nok_country TEXT,
  nok_country_code TEXT,
  nok_phone TEXT,

  -- Academic
  program_code TEXT,
  program_name TEXT,
  entry_level TEXT,
  study_mode TEXT,
  preferred_session TEXT,
  preferred_semester TEXT,

  -- Account
  password_hash TEXT,
  identity TEXT,
  role TEXT DEFAULT 'applicant',

  -- Documents
  waec_file_path TEXT,
  neco_file_path TEXT,
  birth_cert_file_path TEXT,
  passport_file_path TEXT,
  transcript_file_path TEXT,
  other_file_path TEXT,

  -- Payment
  payment_status TEXT DEFAULT 'unpaid',
  payment_reference TEXT,
  payment_amount NUMERIC(10,2),
  payment_currency TEXT DEFAULT 'NGN',
  payment_paid_at TIMESTAMPTZ,

  -- Workflow
  status TEXT DEFAULT 'draft', -- draft, submitted, under_review, approved, rejected
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Payments
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  applicant_id INTEGER NOT NULL REFERENCES applicants(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,

  amount NUMERIC(10,2) NOT NULL,
  currency TEXT NOT NULL DEFAULT 'NGN',
  reference TEXT NOT NULL UNIQUE,
  provider_reference TEXT,

  status TEXT NOT NULL DEFAULT 'pending', -- pending, success, failed, cancelled
  provider TEXT NOT NULL DEFAULT 'paystack',
  metadata JSONB,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sessions (for express-session + connect-pg-simple)
CREATE TABLE IF NOT EXISTS user_sessions (
  sid VARCHAR PRIMARY KEY,
  sess JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);

CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions (expire);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS applicants_email_unique ON applicants (email);
CREATE UNIQUE INDEX IF NOT EXISTS applicants_identity_unique ON applicants (identity) WHERE identity IS NOT NULL;
CREATE INDEX IF NOT EXISTS applicants_status_index ON applicants (status);
CREATE INDEX IF NOT EXISTS payments_applicant_id_index ON payments (applicant_id);
CREATE INDEX IF NOT EXISTS payments_reference_index ON payments (reference);
CREATE INDEX IF NOT EXISTS payments_status_index ON payments (status);