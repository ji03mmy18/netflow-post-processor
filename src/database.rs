use std::{net::Ipv4Addr, collections::HashMap};

use chrono::{Datelike, NaiveDate};
use postgres::NoTls;
use postgres_inet::MaskedIpAddr;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;

use crate::netflow::NetflowV4;

pub struct FlowCount {
    extra_in: i64,
    extra_out: i64,
    intra_in: i64,
    intra_out: i64
}

impl Default for FlowCount {
    fn default() -> Self {
        Self { extra_in: 0, extra_out: 0, intra_in: 0, intra_out: 0 }
    }
}

pub fn cache_date(flow: NetflowV4, flow_type: u8, cache: &mut HashMap<String, FlowCount>) {
    let date: Vec<&str> = flow.first.split('T').collect();
    let hour: Vec<&str> = date[1].split(":").collect();
    let bytes = i64::try_from(flow.in_bytes).expect("i64 Parse error: size not enough!");
    match flow_type {
        1 => {
            let record = cache.entry(format!("{}_{}_{}",flow.dst4_addr, date[0], hour[0]))
                .or_insert(FlowCount { ..Default::default() });
            record.extra_in += bytes;
        },
        2 => {
            let record = cache.entry(format!("{}_{}_{}",flow.src4_addr, date[0], hour[0]))
                .or_insert(FlowCount { ..Default::default() });
            record.extra_out += bytes;
        },
        3 => {
            let record = cache.entry(format!("{}_{}_{}",flow.dst4_addr, date[0], hour[0]))
                .or_insert(FlowCount { ..Default::default() });
            record.intra_in += bytes;
            let record = cache.entry(format!("{}_{}_{}",flow.src4_addr, date[0], hour[0]))
                .or_insert(FlowCount { ..Default::default() });
            record.intra_out += bytes;
        },
        _ => ()
    }
}

pub fn store_cache(cache: HashMap<String, FlowCount>, pool: &Pool<PostgresConnectionManager<NoTls>>) {
    for (key, flow) in cache {
        let keys: Vec<&str> = key.split("_").collect();
        let ip: MaskedIpAddr = From::from(keys[0].parse::<Ipv4Addr>().expect("msg"));
        let date = NaiveDate::parse_from_str(keys[1], "%Y-%m-%d").expect("NaiveDate Parse error: ");
        let hour: i16 = keys[2].parse().unwrap();

        let nf_name = format!("nf_{}", date.format("%Y_%m").to_string());
        update_flow(nf_name, ip, date, hour, flow, pool.get().unwrap());
    }
}

fn update_flow(nf_name: String, ip: MaskedIpAddr, date: NaiveDate, hour: i16, flow: FlowCount, mut client: PooledConnection<PostgresConnectionManager<NoTls>>) {
    client.execute(&format!("INSERT INTO {nf_name} (ip, date, hour, intra_in, intra_out, extra_in, extra_out)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (ip, date, hour)
        DO UPDATE SET
            intra_in = {nf_name}.intra_in + EXCLUDED.intra_in,
            intra_out = {nf_name}.intra_out + EXCLUDED.intra_out,
            extra_in = {nf_name}.extra_in + EXCLUDED.extra_in,
            extra_out = {nf_name}.extra_out + EXCLUDED.extra_out;"),
        &[&ip, &date, &hour, &flow.intra_in, &flow.intra_out, &flow.extra_in, &flow.extra_out]).unwrap();
}

pub fn check_dbtable(pool: &Pool<PostgresConnectionManager<NoTls>>) {
    let dt = chrono::offset::Local::now();
    let mut client = pool.get().unwrap();
    let curr_year = dt.year();
    let next_year = if dt.month() == 12 { dt.year() + 1 } else { dt.year() };
    let curr_month = dt.month();
    let next_month = if dt.month() == 12 { 1 } else { dt.month() + 1 };
    let nf_name: [String; 2] = [format!("nf_{}_{:0>2}", curr_year, curr_month), format!("nf_{}_{:0>2}", next_year, next_month)];
    
    for nftable in nf_name {
        let rows = client.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = $1;", &[&nftable])
            .expect("DB Query error: select current month nf table");
        let exist: i64 = rows[0].get(0);
        println!("Table Exist: {} => {}", nftable, exist);
        if exist == 0 {
            client.execute(&format!("CREATE TABLE {nftable} (
                ip inet NOT NULL,
                date date NOT NULL,
                hour smallint NOT NULL,
                intra_in bigint DEFAULT 0,
                intra_out bigint DEFAULT 0,
                extra_in bigint DEFAULT 0,
                extra_out bigint DEFAULT 0,
                CONSTRAINT valid_hours CHECK ((hour >= 0) AND (hour <= 23)),
                CONSTRAINT valid_ip CHECK (ip << '140.125.0.0/16'::inet),
                PRIMARY KEY (ip, date, hour));"),
                &[]).unwrap();
        }
    }
}