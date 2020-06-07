/*
 * source code modified from ctclient crate, originally found at github.com/micromaomao/ctclient
 *
 * Copyright 2020 <m@maowtm.org>, Ryan Barry <ryan@nuclearice.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 *   the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use std::convert::TryInto;

#[derive(Debug)]
pub enum Error {
    OpenSSLErrorStack(openssl::error::ErrorStack),
    MalformedLeafInput(String),
}

pub struct TimestampedEntryData {
    pub subject: Vec<String>,
    pub alternate: Vec<String>,
    pub timestamp: u64,
}

fn err_invalid() -> Error {
    Error::MalformedLeafInput("Invalid leaf data.".to_string())
}

impl TimestampedEntryData {
    pub fn from_raw(leaf_input: &[u8], extra_data: &[u8]) -> Result<Self, Error> {
        /*
         type MerkleTreeLeaf struct {
           Version          Version           `tls:"maxval:255"`
           LeafType         MerkleLeafType    `tls:"maxval:255"`
           TimestampedEntry *TimestampedEntry `tls:"selector:LeafType,val:0"`
         }
        */
        if leaf_input.len() < 2 {
            return Err(err_invalid());
        }
        let mut leaf_slice = &leaf_input[..];
        let version = u8::from_be_bytes([leaf_slice[0]]);
        let leaf_type = u8::from_be_bytes([leaf_slice[1]]);
        if version != 0 || leaf_type != 0 {
            return Err(err_invalid()); // TODO should ignore.
        }
        leaf_slice = &leaf_slice[2..];
        /*
         type TimestampedEntry struct {
           Timestamp    uint64
           EntryType    LogEntryType   `tls:"maxval:65535"`
           X509Entry    *ASN1Cert      `tls:"selector:EntryType,val:0"`
           PrecertEntry *PreCert       `tls:"selector:EntryType,val:1"`
           JSONEntry    *JSONDataEntry `tls:"selector:EntryType,val:32768"`
           Extensions   CTExtensions   `tls:"minlen:0,maxlen:65535"`
         }
         type PreCert struct {
           IssuerKeyHash  [sha256.Size]byte
           TBSCertificate []byte `tls:"minlen:1,maxlen:16777215"` // DER-encoded TBSCertificate
         }
        */

        if leaf_slice.len() < 8 + 2 {
            return Err(err_invalid());
        }
        let timestamp = u64::from_be_bytes(leaf_slice[0..8].try_into().unwrap()); // unix epoch millis

        leaf_slice = &leaf_slice[8..];
        let entry_type = u16::from_be_bytes([leaf_slice[0], leaf_slice[1]]);

        leaf_slice = &leaf_slice[2..];
        let parse_result: Result<openssl::x509::X509, Error> = match entry_type {
            0 => parse_der(leaf_slice),
            1 => parse_der(extra_data),
            _ => Err(err_invalid()), // TODO should ignore.
        };

        match parse_result {
            Ok(cert) => {
                let sn = cert
                    .subject_name()
                    .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                    .map(|x| x.data().as_utf8())
                    .filter_map(|x| x.ok())
                    .map(|x| String::from(AsRef::<str>::as_ref(&x)))
                    .collect();
                Ok(TimestampedEntryData {
                    timestamp: timestamp,
                    subject: sn,
                    alternate: [].to_vec(),
                })
            }
            Err(e) => Err(e),
        }
    }
}

fn parse_der(data: &[u8]) -> Result<openssl::x509::X509, Error> {
    if data.len() < 3 {
        return Err(err_invalid());
    }
    let len = u32::from_be_bytes([0, data[0], data[1], data[2]]);

    let dataslice = &data[3..];
    if dataslice.len() < len as usize {
        return Err(err_invalid());
    }
    let x509_data = &dataslice[..len as usize];

    match openssl::x509::X509::from_der(x509_data) {
        Ok(c) => Ok(c),
        Err(e) => Err(Error::OpenSSLErrorStack(e)),
    }
}
