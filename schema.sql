CREATE TABLE public.nf_YYYY_MM (
    ip inet NOT NULL,
    date date NOT NULL,
    hour smallint NOT NULL,
    intra_in bigint DEFAULT 0,
    intra_out bigint DEFAULT 0,
    extra_in bigint DEFAULT 0,
    extra_out bigint DEFAULT 0,
    CONSTRAINT valid_hours CHECK (((hour >= 0) AND (hour <= 23))),
    CONSTRAINT valid_ip CHECK (ip << '140.125.0.0/16'::inet),
    PRIMARY KEY (id, date, hour)
);