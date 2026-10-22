-- Intentionally empty: the Postgres twin of this migration adds
-- refresh_families, the row lock its READ COMMITTED writers need around a
-- refresh-token rotation. SQLite has a single writer, so SaveRefresh's
-- guarded INSERT is already atomic (state/sqlite/refresh.go). The file
-- exists because the two backends' migrations are numbered as pairs.
SELECT 1;
