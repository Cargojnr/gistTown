

--mitigation queries 
-- USERS
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password TEXT NOT NULL,
  profile_picture TEXT,
  active_status BOOLEAN DEFAULT FALSE,
  verified BOOLEAN DEFAULT FALSE,
  display_user BOOLEAN DEFAULT FALSE,           -- "stealth mode" flag
  login_code VARCHAR(6),                        -- for one-time login code
  login_code_expires TIMESTAMPTZ,               -- expiry for login_code
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- SECRETS (if you use it; join with users)
CREATE TABLE IF NOT EXISTS secrets (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  category VARCHAR(50),
  color VARCHAR(30),
  reactions JSONB DEFAULT '{}'::jsonb,
  reported BOOLEAN DEFAULT FALSE,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- EAVEDROPS (your “followers”)
CREATE TABLE IF NOT EXISTS eavedrops (
  id SERIAL PRIMARY KEY,
  audience_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (audience_id, target_id)
);

-- AUDIO bookmarks (since you queried this)
CREATE TABLE IF NOT EXISTS bookmarks (
  id SERIAL PRIMARY KEY,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  audio_id INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TEXT bookmarks (you had 'bookmarkss' earlier—fixing to 'text_bookmarks')
CREATE TABLE IF NOT EXISTS text_bookmarks (
  id SERIAL PRIMARY KEY,
  user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (user_id, secret_id)
);

-- LOGIN AUDIT (you insert on successful login)
CREATE TABLE IF NOT EXISTS login_audit (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address TEXT,
  user_agent TEXT,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE "audios"
ADD COLUMN IF NOT EXISTS reactions JSONB DEFAULT '{}';

ALTER TABLE comments ADD COLUMN audio_id INTEGER REFERENCES "audios"(id);

ALTER TABLE users ADD COLUMN avatar_alt VARCHAR(50);