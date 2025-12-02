begin;
select _v.register_patch('001-base-schema', ARRAY['000-setup'], NULL);

create table sites (
	id serial primary key,
	name text not null,
	info text,
	perimeter path
);

create table gateways (
	id serial primary key,
	site int references sites(id),
	name text not null,
	info text,
	location point
);

create table watchers (
	id serial primary key,
	gateway int references gateways(id),
	name text not null,
	info text,
	location point not null
);

create table reports (
	moment timestamp,
	watcher int references watchers(id),
	report int, -- a numeric value corresponding to the difference since the last report, positive or negative
	primary key (moment, watcher)
) with (
	timescaledb.hypertable,
	timescaledb.partition_column='moment',
	timescaledb.segmentby='watcher'
);

commit;
