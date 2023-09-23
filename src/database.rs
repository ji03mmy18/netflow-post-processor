use std::{net::Ipv4Addr, collections::HashMap};

use chrono::{Datelike, NaiveDate};
use postgres::NoTls;
use postgres_inet::MaskedIpAddr;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use uuid::Uuid;

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
        let ip = keys[0].to_string();
        let date = NaiveDate::parse_from_str(keys[1], "%Y-%m-%d").expect("NaiveDate Parse error: ");
        let hour: i16 = keys[2].parse().unwrap();

        let nf_name = format!("nf_{}", date.format("%Y_%m").to_string());
        let ip_ref = get_ip_ref(From::from(ip.parse::<Ipv4Addr>().expect("msg")), pool.get().unwrap());
        let nf_id = get_nf_id(ip_ref, &date, &hour, &nf_name, pool.get().unwrap());
        update_flow(nf_id, &nf_name, flow, pool.get().unwrap());
    }
}

fn get_ip_ref(ip_addr: MaskedIpAddr, mut client: PooledConnection<PostgresConnectionManager<NoTls>>) -> Uuid {
    let mut rows = client.query("SELECT id FROM ipset WHERE ip_addr = $1;", &[&ip_addr])
        .expect("DB Query failed: select ip from ipset");
    if rows.len() == 0 {
        client.execute("INSERT INTO ipset (ip_addr) VALUES ($1);", &[&ip_addr]).unwrap();
        rows = client.query("SELECT id FROM ipset WHERE ip_addr = $1;", &[&ip_addr])
            .expect("DB Query failed: select ip from ipset");
    }
    return rows[0].get(0);
}

fn get_nf_id(ip_ref: Uuid, date: &NaiveDate, time: &i16, nf_name: &String, mut client: PooledConnection<PostgresConnectionManager<NoTls>>) -> Uuid {
    let mut rows = client.query(&format!("SELECT id FROM {nf_name} WHERE ip_ref = $1 AND date = $2 AND time = $3;"), &[&ip_ref, &date, &time])
        .expect("DB Query failed: select nf from nf table");
    if rows.len() == 0 {
        client.execute(&format!("INSERT INTO {nf_name} (ip_ref, date, time) VALUES ($1, $2, $3);"), &[&ip_ref, &date, &time]).unwrap();
        rows = client.query(&format!("SELECT id FROM {nf_name} WHERE ip_ref = $1 AND date = $2 AND time = $3;"), &[&ip_ref, &date, &time])
            .expect("DB Query failed: select nf from nf table");
    }
    return rows[0].get(0);
}

fn update_flow(nf_id: Uuid, nf_name: &String, flow: FlowCount, mut client: PooledConnection<PostgresConnectionManager<NoTls>>) {
    client.execute(&format!("UPDATE {nf_name} SET extra_in = extra_in + $1, extra_out = extra_out + $2,
        intra_in = intra_in + $3, intra_out = intra_out + $4 WHERE id = $5;"),
        &[&flow.extra_in, &flow.extra_out, &flow.intra_in, &flow.intra_out, &nf_id]).unwrap();
}

pub fn init_dbtable(pool: &Pool<PostgresConnectionManager<NoTls>>) {
    let mut client = pool.get().unwrap();
    let rows = client.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'ipset';", &[])
        .expect("DB Query error: select current month nf table");
    let exist: i64 = rows[0].get(0);
    if exist == 0 {
        client.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";", &[]).unwrap();
        client.execute("COMMENT ON EXTENSION \"uuid-ossp\" IS 
            'generate universally unique identifiers (UUIDs)';", &[]).unwrap();
        client.execute("CREATE TABLE ipset (
            id uuid DEFAULT uuid_generate_v4() NOT NULL,
            ip_addr inet NOT NULL,
            total bigint DEFAULT 0,
            PRIMARY KEY (id));",
            &[]).unwrap();
    }
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
                id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
                ip_ref uuid NOT NULL,
                date date DEFAULT CURRENT_DATE NOT NULL,
                \"time\" smallint NOT NULL,
                intra_in bigint DEFAULT 0,
                intra_out bigint DEFAULT 0,
                extra_in bigint DEFAULT 0,
                extra_out bigint DEFAULT 0,
                CONSTRAINT valid_hours CHECK (((\"time\" >= 0) AND (\"time\" <= 23))),
                CONSTRAINT fk_ip_ref FOREIGN KEY (ip_ref) REFERENCES public.ipset(id),
                PRIMARY KEY (id));"),
                &[]).unwrap();
        }
    }
}