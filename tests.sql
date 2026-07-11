\c cda;

create extension if not exists pgtap;

\i tests/002-auth.sql
\i tests/004-rls.sql
\i tests/005-masking.sql
\i tests/006-ingest.sql
\i tests/007-create.sql
\i tests/008-write.sql

drop extension pgtap;
