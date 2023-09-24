use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/*
#[derive(Serialize, Deserialize, Debug)]
pub struct Netflow {
    r#type: String,
    sampled: u8,
    export_sysid: i8,
    first: String,
    last: String,
    received: String,
    in_packets: u16,
    in_bytes: u64,
    proto: u8,
    tcp_flags: String,
    src_port: u16,
    dst_port: u16,
    src_tos: u8,
    src4_addr: Option<String>,
    dst4_addr: Option<String>,
    src6_addr: Option<String>,
    dst6_addr: Option<String>,
    src_geo: String,
    dst_geo: String,
    input_snmp: u32,
    output_snmp: u32,
    src_mask: u8,
    dst_mask: u8,
    src_net: String,
    dst_net: String,
    fwd_status: u8,
    direction: u8,
    dst_tos: u8,
    ip4_router: String,
    label: String
}
 */

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetflowV4 {
    pub first: String,
    pub last: String,
    pub in_packets: u32,
    pub in_bytes: u64,
    pub src4_addr: String,
    pub dst4_addr: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetflowV6 {
    pub first: String,
    pub last: String,
    pub in_packets: u32,
    pub in_bytes: u64,
    pub src6_addr: String,
    pub dst6_addr: String,
}

pub fn parse_data(file_list: Vec<String>) -> Vec<NetflowV4> {
    let mut full_file_name: Vec<String> = Vec::new();
    let mut netflow4: Vec<NetflowV4> = Vec::new();
    let mut netflow6: Vec<NetflowV6> = Vec::new();

    for file in file_list {
        full_file_name.push("/data/netflow/".to_string() + &file);
    }

    for file_path in full_file_name {
        let json_flow = Command::new("nfdump")
            .args(["-r", file_path.as_str(), "-o", "json"])
            .output();

        //當nfdump輸出至stdout的內容有效時
        if let Ok(json_flow) = json_flow {
            //將stdout內容從Buffer中取出，轉換成String
            let stdout = match String::from_utf8(json_flow.stdout) {
                Ok(out) => out,
                Err(_) => break,
            };
            //將json內容轉換成serde_json的Value物件，方便彈性使用
            let vs: Vec<Value> = match serde_json::from_str(&stdout) {
                Ok(v) => v,
                Err(err) => {
                    println!("Json Parse Failed: {}", err);
                    continue;
                },
            };
            //將Value物件根據v4或v6進行歸類，學校流量分析僅處理v4
            for v in vs {
                let packets_u64 = v["in_packets"].as_u64().expect("Netflow in_packets Parsing Error!");
                let packets = u32::try_from(packets_u64).expect("Error occurred while converting u64 to u16!");
                let bytes = v["in_bytes"].as_u64().expect("Netflow in_bytes Parsing Error!");

                if v["src6_addr"] == Value::Null && v["dst6_addr"] == Value::Null {
                    netflow4.push(NetflowV4 { 
                        first: v["first"].as_str().unwrap().to_string(),
                        last: v["last"].as_str().unwrap().to_string(),
                        in_packets: packets,
                        in_bytes: bytes,
                        src4_addr: v["src4_addr"].as_str().unwrap().to_string(),
                        dst4_addr: v["dst4_addr"].as_str().unwrap().to_string()
                    });
                } else {
                    netflow6.push(NetflowV6 { 
                        first: v["first"].as_str().unwrap().to_string(), 
                        last: v["last"].as_str().unwrap().to_string(), 
                        in_packets: packets, 
                        in_bytes: bytes, 
                        src6_addr: v["src4_addr"].as_str().unwrap().to_string(), 
                        dst6_addr: v["dst4_addr"].as_str().unwrap().to_string()
                    });
                }
            }
        }
    }

    return netflow4;
}