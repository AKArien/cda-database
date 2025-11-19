begin;
select _v.register_patch('000-base-schema', NULL, NULL);

create schema private;

create table private.sites (
	id int serial primary key,
	name text not null,
	info text,
	perimeter path not null
);

create table private.gateways (
	id int serial primary key,
	site int foreign key sites.id,
	location point,
);

create table private.watchers (
	id int serial primary key,
	gateway int foreign key references gateways.id,
	location point not null,
);

create table private.reports (
	moment timestamp,
	watcher int foreign key references watchers.id,
	report int, -- a numeric value corresponding to the difference since the last report, positive or negative
	primary key (moment, watcher)
) with (
	timescaledb.hypertable,
	timescaledb.partition_column='moment',
	timescaledb.segmentby='watcher'
);

commit;
