CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';

CREATE TABLE public.ipset (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ip_addr inet NOT NULL,
    total bigint DEFAULT 0,
    PRIMARY KEY (id)
);

CREATE TABLE public.nf_YYYY_MM (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ip_ref uuid NOT NULL,
    date date DEFAULT CURRENT_DATE NOT NULL,
    "time" smallint NOT NULL,
    intra_in bigint DEFAULT 0,
    intra_out bigint DEFAULT 0,
    extra_in bigint DEFAULT 0,
    extra_out bigint DEFAULT 0,
    CONSTRAINT valid_hours CHECK ((("time" >= 0) AND ("time" <= 23))),
    CONSTRAINT fk_ip_ref FOREIGN KEY (ip_ref) REFERENCES public.ipset(id),
    PRIMARY KEY (id)
);