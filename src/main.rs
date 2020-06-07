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

    println!("common names in cert: {:?}", tsedat.Subject);
}
