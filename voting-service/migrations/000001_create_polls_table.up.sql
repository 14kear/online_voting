DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'poll_status') THEN
CREATE TYPE poll_status AS ENUM ('active', 'not-active');
END IF;
END$$;

CREATE TABLE polls (
    id          SERIAL PRIMARY KEY,
    title       VARCHAR(255)             NOT NULL,
    description TEXT,
    creator_id  INT                      NOT NULL,
    status      poll_status              NOT NULL DEFAULT 'active',
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_polls_creator_id ON polls (creator_id);
CREATE INDEX idx_polls_status ON polls (status);