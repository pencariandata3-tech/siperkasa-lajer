
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  capacity INTEGER NOT NULL DEFAULT 390 CHECK (capacity > 0),
  occupants INTEGER NOT NULL DEFAULT 939 CHECK (occupants >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO settings (id, capacity, occupants)
VALUES (1, 390, 939)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(30) NOT NULL CHECK (role IN ('admin','kepala_kplp','operator')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blocks (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(120) NOT NULL UNIQUE,
  capacity INTEGER NOT NULL DEFAULT 0 CHECK (capacity >= 0),
  occupants INTEGER NOT NULL DEFAULT 0 CHECK (occupants >= 0),
  threat INTEGER NOT NULL DEFAULT 3 CHECK (threat BETWEEN 1 AND 5),
  notes TEXT DEFAULT '',
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wbp_risks (
  id BIGSERIAL PRIMARY KEY,
  identity_label VARCHAR(120) NOT NULL,
  registration_no VARCHAR(120) DEFAULT '',
  block_id BIGINT REFERENCES blocks(id) ON DELETE SET NULL,
  violation INTEGER NOT NULL DEFAULT 0 CHECK (violation BETWEEN 0 AND 5),
  conflict INTEGER NOT NULL DEFAULT 0 CHECK (conflict BETWEEN 0 AND 5),
  escape INTEGER NOT NULL DEFAULT 0 CHECK (escape BETWEEN 0 AND 5),
  contraband INTEGER NOT NULL DEFAULT 0 CHECK (contraband BETWEEN 0 AND 5),
  notes TEXT DEFAULT '',
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patrols (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  block_id BIGINT REFERENCES blocks(id) ON DELETE SET NULL,
  officer VARCHAR(160) NOT NULL,
  level VARCHAR(30) NOT NULL CHECK (level IN ('Normal','Perlu Perhatian','Kritis')),
  finding TEXT NOT NULL,
  action TEXT NOT NULL,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  block_id BIGINT REFERENCES blocks(id) ON DELETE SET NULL,
  incident_type VARCHAR(80) NOT NULL,
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('Rendah','Sedang','Tinggi')),
  description TEXT NOT NULL,
  action TEXT NOT NULL,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  username VARCHAR(80),
  action VARCHAR(80) NOT NULL,
  entity VARCHAR(80) NOT NULL,
  entity_id VARCHAR(80),
  detail JSONB DEFAULT '{}'::jsonb,
  ip VARCHAR(100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wbp_block ON wbp_risks(block_id);
CREATE INDEX IF NOT EXISTS idx_patrol_time ON patrols(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_time ON incidents(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at DESC);
