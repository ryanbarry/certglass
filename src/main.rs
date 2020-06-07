fn main() {
    let leaf1raw = include_bytes!("../lets_encrypt_ct_leaf2.dat");
    let leaf1extraraw = include_bytes!("../lets_encrypt_ct_leaf2extra.dat");
    if let Ok(leaf1) = ctclient::internal::Leaf::from_raw(leaf1raw, leaf1extraraw) {
        if !leaf1.is_pre_cert {
            for cert in leaf1.x509_chain {
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
        }else {
            println!("it's a pre-cert!");
        }
    } else {
        println!("couldn't parse");
    }
}
