use std::{
    sync::Arc, 
    error::Error, 
    path::Path,
    os::fd::IntoRawFd,
};

use clap::Parser;
use etherparse::*;

use parquet::{
    file::{
        properties::WriterProperties,
        writer::SerializedFileWriter,
    }, 
    schema::parser::parse_message_type,
    record::RecordWriter,
};

mod schema;
use crate::schema::*;

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    pcap_filename: String,
    #[arg(short, long)]
    num:           Option<usize>,
    #[arg(short, long)]
    out_dir:       Option<String>,
}

fn create_writer(schema: &str, path: &Path) -> SerializedFileWriter<std::fs::File> {
    let schema = Arc::new(parse_message_type(schema).unwrap());
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(parquet::basic::Compression::SNAPPY)
            .build()
    );
    let file = std::fs::File::create(path).unwrap();
    SerializedFileWriter::new(file, schema, props).unwrap()
}

fn mac_to_u64(mac_bytes: &[u8; 6]) -> u64 {
    let mut padded = [0u8; 8];
    padded[2..8].copy_from_slice(mac_bytes);
    u64::from_be_bytes(padded)
}

struct HeaderRows {
    meta: Vec<Meta>,
    eth:  Vec<EthHeaders>,
    vlan: Vec<VlanHeaders>,
    ip:   Vec<IPHeaders>,
    udp:  Vec<UDPHeaders>,
    tcp:  Vec<TCPHeaders>,
}

fn process_pkt(
    index: u64, 
    pkt: &pcap::Packet, 
    net_hdr_vec: &mut HeaderRows
) -> Result<(), Box<dyn Error>> {

    //Parse the packet
    let hdrs = SlicedPacket::from_ethernet(pkt.data)?;

    //Write the metadata
    let nsec = pkt.header.ts.tv_sec * 1_000_000_000 + pkt.header.ts.tv_usec * 1_000;

    net_hdr_vec.meta.push(Meta {
        index,
        nsec, 
    });

    //Always expect an Ethernet header, so it's absense is an error
    match hdrs.link.ok_or("No Ethernet header")? {
        etherparse::LinkSlice::Ethernet2(eth) => {
            net_hdr_vec.eth.push(EthHeaders {
                index,

                dst_mac:   mac_to_u64(&eth.destination()),
                src_mac:   mac_to_u64(&eth.source()),
                ethertype: eth.ether_type(),

            });
        }
    }

    //Vlan
    if let Some(vlan) = hdrs.vlan {
        match vlan {
            etherparse::VlanSlice::SingleVlan(single) => {
                net_hdr_vec.vlan.push(VlanHeaders {
                    index,
        
                    vlan_identifier: single.vlan_identifier(),
                    ethertype:       single.ether_type(),
                });
            }
            etherparse::VlanSlice::DoubleVlan(_double) => {}
        }
    };

    match hdrs.ip {
        Some(etherparse::InternetSlice::Ipv4(ipv4, _)) => {

            net_hdr_vec.ip.push(IPHeaders {
                index,

                src_ip:           u32::from_be_bytes(ipv4.source()) as u64,
                dst_ip:           u32::from_be_bytes(ipv4.destination()) as u64,
                proto:            ipv4.protocol(),
                len:              ipv4.total_len(),

                dont_fragment:    ipv4.dont_fragment(),
                more_fragments:   ipv4.more_fragments(),
                fragments_offset: ipv4.fragments_offset(),
            });

        }
        _ => return Ok(())
    }

    match hdrs.transport {
        
        Some(etherparse::TransportSlice::Udp(udp)) => {
            net_hdr_vec.udp.push(UDPHeaders {
                index,

                src_port:  udp.source_port(),
                dst_port:  udp.destination_port(),
                length:    udp.length(),
                checksum:  udp.checksum(),
            });
        }
        
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            net_hdr_vec.tcp.push(TCPHeaders {
                index,

                src_port:    tcp.source_port(),
                dst_port:    tcp.destination_port(),
                seq_num:     tcp.sequence_number(),
                ack_num:     tcp.acknowledgment_number(),
                data_offset: tcp.data_offset(),

                window:      tcp.window_size(),
                checksum:    tcp.checksum(),
                urgent_ptr:  tcp.urgent_pointer(),

                syn:         tcp.syn(),
                fin:         tcp.fin(),
                rst:         tcp.rst(),
                psh:         tcp.psh(),
                ack:         tcp.ack(),
            });
        }

        _ => return Ok(())
    }

    Ok(())
}

fn write_batch<T, A>(vec: &mut Vec<A>, writer: &mut SerializedFileWriter<std::fs::File>) 
where 
for <'a> &'a[A]: RecordWriter<T>,
{
    let mut row_group_writer = writer.next_row_group().unwrap();
    (&vec[..]).write_to_row_group(&mut row_group_writer).unwrap();
    row_group_writer.close().unwrap();
    vec.clear();
}

fn write_remaining<T, A>(vec: &mut Vec<A>, writer: &mut SerializedFileWriter<std::fs::File>) 
where 
for <'a> &'a[A]: RecordWriter<T>,
{
    if !vec.is_empty() {
        write_batch(vec, writer);
    }
}

const MAX_ROWS: usize = 10000;

fn write_chunk<T, A>(vec: &mut Vec<A>, writer: &mut SerializedFileWriter<std::fs::File>) 
where 
for <'a> &'a[A]: RecordWriter<T>,
{
    if vec.len() >= MAX_ROWS {
        write_batch(vec, writer);
    }
}

fn main() {
    //Get the args
    let args = Args::parse();

    /*
     * Get args.num files in alphabetical order starting from args.pcap_filename
     */
    let path = Path::new(&args.pcap_filename);

    let mut paths: Vec<_> 
        = std::fs::read_dir(path.parent().unwrap()).unwrap()
            .map(|r| r.unwrap())
            .filter(|file| file.path().extension() == path.extension())
            .collect();

    paths.sort_by_key(|dir| dir.path());
    let index = paths.iter().position(|x| x.path().as_os_str() == path.as_os_str()).unwrap();

    let num_files = args.num.unwrap_or(1);
    let files     = &paths[index..index+num_files];

    println!("Input files:");
    for path in files {
        println!("{}", path.path().display())
    }

    //Create the output directory, if required
    if let Some(dir) = args.out_dir.as_ref() {
        let _ = std::fs::create_dir(dir);
    }

    let mut cap_num: u64 = 0;
    let mut total: u64 = 0;

    std::thread::scope(|s| {

        let mut handles = vec![];

        for f in files {

            let cap_num_s = cap_num;
            let args      = &args;

            let handle = s.spawn(move || {
                let p     = f.path();
                let ext   = p.extension();
                let fname = f.file_name().into_string().unwrap();

                let out_path  = match args.out_dir.as_ref() {
                    Some(out) => Path::new(".").join(out),
                    None      => std::path::PathBuf::from("."),
                };

                //Parquet writers
                let mut meta_writer = create_writer(META_SCHEMA,     &out_path.join(format!("{}.meta.parquet", fname)));
                let mut eth_writer  = create_writer(ETH_HDR_SCHEMA,  &out_path.join(format!("{}.eth.parquet",  fname)));
                let mut vlan_writer = create_writer(VLAN_HDR_SCHEMA, &out_path.join(format!("{}.vlan.parquet", fname)));
                let mut ip_writer   = create_writer(IP_HDR_SCHEMA,   &out_path.join(format!("{}.ip.parquet",   fname)));
                let mut udp_writer  = create_writer(UDP_HDR_SCHEMA,  &out_path.join(format!("{}.udp.parquet",  fname)));
                let mut tcp_writer  = create_writer(TCP_HDR_SCHEMA,  &out_path.join(format!("{}.tcp.parquet",  fname)));

                let mut vecs = HeaderRows {
                    meta: Vec::new(),
                    vlan: Vec::new(),
                    eth:  Vec::new(),
                    ip:   Vec::new(),
                    udp:  Vec::new(),
                    tcp:  Vec::new(),
                };

                let mut cap = if ext.and_then(std::ffi::OsStr::to_str) == Some("xz") {
                    let mut proc 
                        = subprocess::Exec::cmd("unxz")
                        .arg("--stdout")
                        .arg("-T 0")
                        .arg(f.path().to_str().unwrap())
                        .stdout(subprocess::Redirection::Pipe)
                        .detached()
                        .popen()
                        .unwrap();

                    let fd      = proc.stdout.take().unwrap().into_raw_fd();
                    unsafe {pcap::Capture::from_raw_fd(fd).unwrap()}
                } else {
                    pcap::Capture::from_file(f.path()).unwrap()
                };

                let mut pkt_num: u64 = 0;

                loop {
                    match cap.next_packet() {
                        Ok(pkt) => {

                            let res = process_pkt(cap_num_s + pkt_num, &pkt, &mut vecs);
                            match res {
                                Ok(())   => {},
                                Err(err) => println!("{}", err),
                            }

                            write_chunk(&mut vecs.meta, &mut meta_writer);
                            write_chunk(&mut vecs.eth,  &mut eth_writer);
                            write_chunk(&mut vecs.vlan, &mut vlan_writer);
                            write_chunk(&mut vecs.ip,   &mut ip_writer);
                            write_chunk(&mut vecs.udp,  &mut udp_writer);
                            write_chunk(&mut vecs.tcp,  &mut tcp_writer);

                            pkt_num += 1;
                        }
                        Err(err) => {
                            println!("{}", err);
                            break;
                        }
                    }
                }

                write_remaining(&mut vecs.meta, &mut meta_writer);
                write_remaining(&mut vecs.eth,  &mut eth_writer);
                write_remaining(&mut vecs.vlan, &mut vlan_writer);
                write_remaining(&mut vecs.ip,   &mut ip_writer);
                write_remaining(&mut vecs.udp,  &mut udp_writer);
                write_remaining(&mut vecs.tcp,  &mut tcp_writer);

                meta_writer.close().unwrap();
                eth_writer.close().unwrap();
                vlan_writer.close().unwrap();
                ip_writer.close().unwrap();
                udp_writer.close().unwrap();
                tcp_writer.close().unwrap();

                pkt_num

            });

            handles.push(handle);

            let base: u64 = 2;
            cap_num += base.pow(48);
        }

        for handle in handles {
            total += handle.join().unwrap();
        }
    });

    println!("Packets processed: {}", total);
}

