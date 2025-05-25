CREATE TABLE options
(
    id         SERIAL PRIMARY KEY,
    poll_id    INT                      NOT NULL,
    text       TEXT                     NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_poll
        FOREIGN KEY (poll_id)
            REFERENCES polls (id)
            ON DELETE CASCADE
);

CREATE INDEX idx_options_poll_id ON options (poll_id);
CREATE INDEX idx_options_created_at ON options (created_at);