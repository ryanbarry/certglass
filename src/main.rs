mod merkle_tree_leaf;

use merkle_tree_leaf::cert_from_leaf;

fn main() {
    let leafinputdat = include_bytes!("../lets_encrypt_ct_leaf1.dat");
    let leafextradat = include_bytes!("../lets_encrypt_ct_leaf1extra.dat");

    let cert = match cert_from_leaf(leafinputdat, leafextradat) {
        Ok(c) => c,
        Err(e) => {
            println!("error parsing cert from MerkleTreeLeaf: {:?}", e);
            return;
        }
    };

    println!(
        "common names in cert: {:?}",
        ctclient::certutils::get_common_names(&cert).unwrap()
    );
    println!(
        "signature alg: {}\nsignature_len: {}",
        cert.signature_algorithm()
            .object()
            .nid()
            .short_name()
            .unwrap(),
        cert.signature().len()
    );

    let leaf = match ctclient::internal::Leaf::from_raw(leafinputdat, leafextradat) {
        Ok(l) => l,
        Err(e) => {
            println!("error parsing from raw: {}", e);
            return;
        }
    };

    if leaf.is_pre_cert {
        println!("it's a precert.");
        return;
    }

    for cert in leaf.x509_chain {
        if let Ok(x509) = openssl::x509::X509::from_der(&cert) {
            if let Ok(names) = ctclient::certutils::get_common_names(&x509) {
                println!("common names: {:?}", names);
            } else {
                println!("got error getting cert common names");
            }
        } else {
            println!("got error doing from_der");
        }
    }
}
