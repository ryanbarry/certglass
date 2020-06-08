mod merkle_tree_leaf;

use merkle_tree_leaf::TimestampedEntryData;

fn main() {
    let leafinputdat = include_bytes!("../lets_encrypt_ct_leaf0.dat");
    let leafextradat = include_bytes!("../lets_encrypt_ct_leaf0extra.dat");

    let tsedat = match TimestampedEntryData::from_raw(leafinputdat, leafextradat) {
        Ok(c) => c,
        Err(e) => {
            println!("error parsing cert from MerkleTreeLeaf: {:?}", e);
            return;
        }
    };

    let parsedtime = chrono::naive::NaiveDateTime::from_timestamp(
        (tsedat.timestamp / 1000) as i64,
        (tsedat.timestamp % 1000 * 1000000) as u32,
    );

    println!("common names in cert: {:?}", tsedat.subject);
    println!("alternate names     : {:?}", tsedat.alternate);
    println!("timestamp           : {}", tsedat.timestamp);
    println!("parsed timestamp    : {}", parsedtime);
}
