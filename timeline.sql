-- connect to the database and ensure every migration is ran
\c cda;

\i migrations/000-setup.sql
\i migrations/001-base-schema.sql
\i migrations/002-auth.sql
\i migrations/003-permissions-management.sql
\i migrations/004-rls-rules.sql
\i migrations/005-column-security.sql
\i migrations/006-api-views.sql