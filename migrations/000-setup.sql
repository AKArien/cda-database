begin;
select _v.register_patch('000-setup', NULL, NULL);

create extension if not exists timescaledb;
create extension if not exists pgcrypto;
create extension if not exists pgjwt;

commit;
