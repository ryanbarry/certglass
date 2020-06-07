fn main() {
    let leafinputdat = include_bytes!("../lets_encrypt_ct_leaf2.dat");

    // giving empty "extra_data" since that holds the cert chain
    // https://tools.ietf.org/html/rfc6962#section-4.6
    let leaf = match ctclient::internal::Leaf::from_raw(leafinputdat, &[0 as u8; 3]) {
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
