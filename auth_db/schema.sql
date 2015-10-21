create table if not exists users (
    account text PRIMARY KEY,
    password text
);

create table if not exists acls (
    ID serial PRIMARY KEY,
    account text,
    type text,
    name text,
    actions text[]
);
