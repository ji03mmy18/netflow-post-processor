use std::{
    thread,
    net::Ipv4Addr,
    collections::HashMap,
    sync::mpsc::channel
};

use chrono::{Datelike, NaiveDate};
use postgres::{NoTls, Transaction};
use postgres_inet::MaskedIpAddr;
use postgres_types::ToSql;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use crate::{netflow::NetflowV4, get_netflow_type};

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

pub fn cache_data_mt(num_threads: usize, flows: Vec<NetflowV4>, cache: &mut Vec<HashMap<String, FlowCount>>) {
    let (tx, rx) = channel();

    // 將flows根據執行緒數量切分，讓資料在各自執行緒中處理
    let chunk_size = flows.len() / num_threads;
    for chunk in flows.chunks(chunk_size) {
        let tx = tx.clone();
        let flows = chunk.to_vec();
        
        thread::spawn(move || {
            let mut cache: HashMap<String, FlowCount> = HashMap::new();
            for flow in flows {
                let flow_type = get_netflow_type(&flow);
                cache_data(flow, flow_type, &mut cache);
            }
            tx.send(cache).expect("Failed to send cache data: ");
        });
    }

    // 收集所有线程的结果
    for _ in 0..num_threads {
        if let Ok(data) = rx.recv() {
            cache.push(data);
        }
    }

}

pub fn cache_data(flow: NetflowV4, flow_type: u8, cache: &mut HashMap<String, FlowCount>) {
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

pub fn store_cache_mt(cache: HashMap<String, FlowCount>, pool: &Pool<PostgresConnectionManager<NoTls>>) {
    let mut table_name: Vec<String> = Vec::new();
    let mut ip_list: Vec<MaskedIpAddr> = Vec::new();
    let mut date_list: Vec<NaiveDate> = Vec::new();
    let mut hour_list: Vec<i16> = Vec::new();
    let mut flow_list: Vec<FlowCount> = Vec::new();
    let mut index: i8 = 1;
    for(key, flow) in cache {
        if index > 100 {
            update_flow_mt(&table_name, &ip_list, &date_list, &hour_list, &flow_list, pool);
            table_name.clear();
            ip_list.clear();
            date_list.clear();
            hour_list.clear();
            flow_list.clear();
            index = 1;
        }
        let keys: Vec<&str> = key.split("_").collect();
        let ip: MaskedIpAddr = From::from(keys[0].parse::<Ipv4Addr>().expect("msg"));
        let date = NaiveDate::parse_from_str(keys[1], "%Y-%m-%d").expect("NaiveDate Parse error: ");
        let hour: i16 = keys[2].parse().unwrap();

        let nf_name = format!("nf_{}", date.format("%Y_%m").to_string());
        table_name.push(nf_name);
        ip_list.push(ip);
        date_list.push(date);
        hour_list.push(hour);
        flow_list.push(flow);
        index += 1;
    }
    update_flow_mt(&table_name, &ip_list, &date_list, &hour_list, &flow_list, pool);
}

fn update_flow_mt(nf_name: &Vec<String>, ip: &Vec<MaskedIpAddr>, date: &Vec<NaiveDate>, hour: &Vec<i16>, flow: &Vec<FlowCount>, pool: &Pool<PostgresConnectionManager<NoTls>>) {
    let length = nf_name.len();
    let first = &nf_name[0];
    match nf_name.iter().all(|name| name == first) {
        true => {
            //println!("Store MT: true");
            let mut params = Vec::<&(dyn ToSql + Sync)>::new();
            let mut i = 1;
            let mut query_start = String::from(format!("INSERT INTO {first} (ip, date, hour, intra_in, intra_out, extra_in, extra_out)VALUES "));
            let query_end = String::from(format!("ON CONFLICT (ip, date, hour)
                DO UPDATE SET
                intra_in = {first}.intra_in + EXCLUDED.intra_in,
                intra_out = {first}.intra_out + EXCLUDED.intra_out,
                extra_in = {first}.extra_in + EXCLUDED.extra_in,
                extra_out = {first}.extra_out + EXCLUDED.extra_out;"));
            for x in 0..length {
                if i == 1 {
                    query_start = format!("{query_start} (${}, ${}, ${}, ${}, ${}, ${}, ${})", i, i+1, i+2, i+3, i+4, i+5, i+6);
                } else {
                    query_start = format!("{query_start}, (${}, ${}, ${}, ${}, ${}, ${}, ${})", i, i+1, i+2, i+3, i+4, i+5, i+6);
                }
                params.push(&ip[x]);
                params.push(&date[x]);
                params.push(&hour[x]);
                params.push(&flow[x].intra_in);
                params.push(&flow[x].intra_out);
                params.push(&flow[x].extra_in);
                params.push(&flow[x].extra_out);
                i = i + 7;
            }
            let mut client = pool.get().unwrap();
            client.execute(&format!("{query_start} {query_end}"), &params).unwrap();
        },
        false => {
            //println!("Store MT: false");
            let mut client = pool.get().unwrap();
            let mut transaction = client.transaction().expect("Create Transaction Error: ");
            for i in 0..100 {
                update_flow(&nf_name[i], &ip[i], &date[i], &hour[i], &flow[i], &mut transaction);
            }
            transaction.commit().expect("Commit Error: ");
        },
    }
}

fn update_flow(nf_name: &String, ip: &MaskedIpAddr, date: &NaiveDate, hour: &i16, flow: &FlowCount, trans: &mut Transaction) {
    trans.execute(&format!("INSERT INTO {nf_name} (ip, date, hour, intra_in, intra_out, extra_in, extra_out)
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
