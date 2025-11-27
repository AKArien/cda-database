-- actions to be only ran once, and that cannot be (very simply) avoided to repeat or integrated in migrations

create database cda;

-- if there is SOURCE_DIR in environment, use it as reference, otherwise, assume current directory. This is primarely for the container image, where we link this into /entrypoint.d/
\c cda
\set sourcedir `echo ${SOURCE_DIR:-.}`
\i :sourcedir/Versioning/install.versioning.sql;
