-- has to be done outside of database, since Versioning is insalled per db
create database cda;
\c cda;

-- if there is SOURCE_DIR in environment, use it as reference, otherwise, assume current directory
\set sourcedir `echo ${SOURCE_DIR:-.}`
\i :sourcedir/Versioning/install.versioning.sql;

begin;
select _v.register_patch('000-setup', NULL, NULL);

create extension if not exists timescaledb;
create extension if not exists pgcrypto;
create extension if not exists pgjwt;

commit;
