CREATE TABLE logs (
                      id         SERIAL PRIMARY KEY,
                      user_id    BIGINT                   NOT NULL,
                      action     TEXT                     NOT NULL,
                      poll_id    INT                      NULL,
                      option_id  INT                      NULL,
                      result_id  INT                      NULL,
                      created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_logs_user_id    ON logs (user_id);
CREATE INDEX idx_logs_action     ON logs (action);
CREATE INDEX idx_logs_created_at ON logs (created_at);
