CREATE TABLE results
(
    id        SERIAL PRIMARY KEY,
    poll_id   INT NOT NULL,
    option_id INT NOT NULL,
    user_id   INT NOT NULL,
    voted_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_poll
        FOREIGN KEY(poll_id)
            REFERENCES polls(id)
            ON DELETE CASCADE,

    CONSTRAINT fk_option
        FOREIGN KEY(option_id)
            REFERENCES options(id)
            ON DELETE CASCADE
);

CREATE INDEX idx_results_poll ON results(poll_id);
CREATE INDEX idx_results_option ON results(option_id);
CREATE INDEX idx_results_user ON results(user_id);
CREATE INDEX idx_results_voted_at ON results(voted_at);
-- одно голосование на одного человека
CREATE UNIQUE INDEX uniq_user_poll ON results(user_id, poll_id);
