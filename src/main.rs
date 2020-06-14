mod ct_log_follower;
mod merkle_tree_leaf;

use ct_log_follower::LogFollower;
use merkle_tree_leaf::TimestampedEntryData;

fn main() {
    let lfc = LogFollower::from_beginning("https://oak.ct.letsencrypt.org/2020/").unwrap();
    let entries = lfc.get_entries(0, 10).unwrap();

    for e in entries {
        match TimestampedEntryData::from_raw(&e.leaf_input, &e.extra_data) {
            Ok(c) => {
                let parsedtime = chrono::naive::NaiveDateTime::from_timestamp(
                    (c.timestamp / 1000) as i64,
                    (c.timestamp % 1000 * 1000000) as u32,
                );

                println!("common names in cert: {:?}", c.subject);
                println!("alternate names     : {:?}", c.alternate);
                println!("timestamp           : {}", c.timestamp);
                println!("parsed timestamp    : {}", parsedtime);
            }
            Err(e) => {
                println!("error parsing cert from MerkleTreeLeaf: {:?}", e);
            }
        }
    }
}
