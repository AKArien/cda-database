\c cda;

begin;
create extension if not exists pgtap;

\i tests/004_rls.sql

rollback;
