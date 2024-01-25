use parquet_derive::ParquetRecordWriter;

#[derive(ParquetRecordWriter)]
pub struct Meta {
    pub index:     u64,
    pub nsec:      i64,
}

pub const META_SCHEMA: &str = "
    message schema {
        REQUIRED INT64 index;
        REQUIRED INT64 nsec;
    }
";

#[derive(ParquetRecordWriter)]
pub struct EthHeaders {
    pub index:     u64,

    pub dst_mac:   u64,
    pub src_mac:   u64,
    pub ethertype: u16,
}

pub const ETH_HDR_SCHEMA: &str = "
    message schema {
        REQUIRED INT64 index;

        REQUIRED INT64 dst_mac;
        REQUIRED INT64 src_mac;
        REQUIRED INT32 ethertype;
    }
";

#[derive(ParquetRecordWriter)]
pub struct VlanHeaders {
    pub index:           u64,

    pub vlan_identifier: u16,
    pub ethertype:       u16,
}

pub const VLAN_HDR_SCHEMA: &str = "
    message schema {
        REQUIRED INT64 index;

        REQUIRED INT32 vlan_identifier;
        REQUIRED INT32 ethertype;
    }
";

#[derive(ParquetRecordWriter)]
pub struct IPHeaders {
    pub index:            u64,

    pub src_ip:           u64,
    pub dst_ip:           u64,
    pub proto:            u8,
    pub len:              u16,

    pub dont_fragment:    bool,
    pub more_fragments:   bool,
    pub fragments_offset: u16,
}

pub const IP_HDR_SCHEMA: &str = "
    message schema {
        REQUIRED INT64   index;

        REQUIRED INT64   src_ip;
        REQUIRED INT64   dst_ip;
        REQUIRED INT32   proto;
        REQUIRED INT32   len;

        REQUIRED BOOLEAN dont_fragment;
        REQUIRED BOOLEAN more_fragments;
        REQUIRED INT32   fragment_offset;
    }
";

#[derive(ParquetRecordWriter)]
pub struct UDPHeaders {
    pub index:     u64,

    pub src_port:  u16,
    pub dst_port:  u16,
    pub length:    u16,
    pub checksum:  u16,
}

pub const UDP_HDR_SCHEMA: &str = "
    message schema {
        REQUIRED INT64 index;

        REQUIRED INT32 src_port;
        REQUIRED INT32 dst_port;
        REQUIRED INT32 length;
        REQUIRED INT32 checksum;
    }
";

#[derive(ParquetRecordWriter)]
pub struct TCPHeaders {
    pub index:       u64,

    pub src_port:    u16,
    pub dst_port:    u16,
    pub seq_num:     u32,
    pub ack_num:     u32,
    pub data_offset: u8,

    pub window:      u16,
    pub checksum:    u16,
    pub urgent_ptr:  u16,

    pub syn:         bool,
    pub fin:         bool,
    pub rst:         bool,
    pub psh:         bool,
    pub ack:         bool,
}

pub const TCP_HDR_SCHEMA: &str = "
    message schema {
        REQUIRED INT64   index;

        REQUIRED INT32   src_port;
        REQUIRED INT32   dst_port;
        REQUIRED INT32   seq_num;
        REQUIRED INT32   ack_num;
        REQUIRED INT32   data_offset;
        REQUIRED INT32   window;
        REQUIRED INT32   checksum;
        REQUIRED INT32   urgent_ptr;
        
        REQUIRED BOOLEAN syn;
        REQUIRED BOOLEAN fin;
        REQUIRED BOOLEAN rst;
        REQUIRED BOOLEAN psh;
        REQUIRED BOOLEAN ack;
    }
";

