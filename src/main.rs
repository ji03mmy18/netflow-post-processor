use std::{
    thread::sleep,
    fs::read_dir,
    time::Duration,
    collections::HashMap,
    env
};

use chrono::Local;
use clokwerk::{Scheduler, TimeUnits, Interval::Sunday, Job};
use database::{
    FlowCount,
    check_dbtable,
    store_cache,
    cache_date
};
use netflow::NetflowV4;
use postgres::{Config, NoTls};
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use regex::Regex;

mod netflow;
mod database;

fn main() {
    println!("Program Start!");
    let pool = get_db_pool();
    let fork1 = pool.clone();
    let fork2 = pool.clone();
    let fork3 = pool.clone();
    println!("DB Pool Created!");
    check_dbtable(&fork3);

    let mut scheduler = Scheduler::new();
    scheduler.every(10.seconds()).run( move || processing(&fork1));
    scheduler.every(Sunday).at("23:00").run( move || check_dbtable(&fork2));
    
    println!("Schedule Task Start!");
    loop {
        scheduler.run_pending();
        sleep(Duration::from_millis(100));
    }
}

fn processing(pool: &Pool<PostgresConnectionManager<NoTls>>) {
    let file_list = get_all_netflow_file();
    
    let flows = netflow::parse_data(file_list);
    println!("\nFlow Count: {}", flows.len());

    let mut cache: HashMap<String, FlowCount> = HashMap::new();

    println!("Store Start!");
    println!("Time => {}", Local::now().format("%H:%M:%S"));
    for flow in flows {
        let flow_type = get_netflow_type(&flow);
        cache_date(flow, flow_type, &mut cache);
    }
    println!("Cache Done: ip count => {}", cache.len());
    store_cache(cache, pool);
    println!("Store Finish!");
    println!("Time => {}", Local::now().format("%H:%M:%S"));
    //刪除處理完成的檔案
}

fn get_all_netflow_file() -> Vec<String> {
    let folder_path = "/data/netflow";
    //let folder_path = "/home/jolly/Rust/netflow-post-processor/data";

    if let Ok(files) = read_dir(folder_path) {
        let mut filenames: Vec<String> = Vec::new();
        let re = Regex::new(r"nfcapd\.\d{12}").unwrap();

        for file in files {
            if let Ok(f) = file {
                if let Some(fname) = f.file_name().to_str() {
                    if re.is_match(fname) {
                        filenames.push(fname.to_string());
                    }
                }
            }
        }

        return filenames;
    } else {
        panic!("Cannot open netflow data folder!");
    }
}

fn get_netflow_type(flow: &NetflowV4) -> u8 {
    let re = Regex::new(r"^(140\.125\.\d{1,3}\.\d{1,3})").expect("Invalid Regex pattern entered, please check again!");
    
    let src_inside = re.is_match(&flow.src4_addr);
    let dst_inside = re.is_match(&flow.dst4_addr);
    // println!("Regex Check: src => {}, dst => {}", src_inside, dst_inside);
    
    if src_inside == false && dst_inside == true {
        return 1;
    } else if src_inside == true && dst_inside == false {
        return 2;
    } else if src_inside == true && dst_inside == true {
        return 3;
    } else {
        //println!("Unexpected IP: src => {}, dst => {}", flow.src4_addr, flow.dst4_addr);
        return 4;
    }
}

fn get_db_pool() -> Pool<PostgresConnectionManager<NoTls>> {
    let config = Config::new()
        .user(&env::var("DB_USER").expect("DB_USER not found!"))
        .password(&env::var("DB_PASSWD").expect("DB_PASSWD not found!"))
        .host(&env::var("DB_HOST").expect("DB_HOST not found!"))
        .port(env::var("DB_PORT").expect("DB_PORT not found!").parse().expect("DB_PORT Parse error!"))
        .dbname(&env::var("DB_NAME").expect("DB_NAME not found!"))
        .to_owned();
    let manager = PostgresConnectionManager::new(config, NoTls);
    match r2d2::Pool::new(manager) {
        Ok(p) => p,
        Err(err) => panic!("Error creating the pool: {err}"),
    }
}