ALTER TABLE "Audios"
ADD COLUMN IF NOT EXISTS reactions JSONB DEFAULT '{}';

ALTER TABLE comments ADD COLUMN audio_id INTEGER REFERENCES "Audios"(id);
