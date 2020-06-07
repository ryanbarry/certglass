fn main() {
    let leafinputdat = include_bytes!("../lets_encrypt_ct_leaf2.dat");
    let leafextradat = include_bytes!("../lets_encrypt_ct_leaf2extra.dat");

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
