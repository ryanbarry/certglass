use serde::Deserialize;

pub struct LogFollower {
    base_url: reqwest::Url,
    http_client: reqwest::blocking::Client,
    latest_size: u64,
}

#[derive(Debug, Deserialize)]
// TODO: private
pub struct CTEntry {
    pub leaf_input: Vec<u8>,
    pub extra_data: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct JsonEntry {
    leaf_input: String,
    extra_data: String,
}

#[derive(Debug, Deserialize)]
struct EntriesResponse {
    entries: Vec<JsonEntry>,
}

#[derive(Debug)]
pub enum Error {
    InvalidArgument(String),
    Unknown(String),
    NetIO(reqwest::Error),
    // The CT server responded with something other than 200.
    InvalidResponseStatus(reqwest::StatusCode),
}

impl LogFollower {
    pub fn from_beginning(base_url: &str) -> Result<Self, Error> {
        if !base_url.ends_with('/') {
            return Err(Error::InvalidArgument("baseUrl must end with /".to_owned()));
        }

        let base_url = reqwest::Url::parse(base_url)
            .map_err(|e| Error::InvalidArgument(format!("Unable to parse URL: {}", &e)))?;

        let http_client = new_http_client()?;

        Ok(Self {
            base_url,
            http_client,
            latest_size: 0,
        })
    }

    // TODO: private
    pub fn get_entries(&self, start: u64, end: u64) -> Result<Vec<CTEntry>, Error> {
        let req_url = self
            .base_url
            .join(&format!("ct/v1/get-entries?start={}&end={}", start, end))
            .unwrap();
        let res = self.http_client.get(req_url).send().map_err(Error::NetIO)?;

        if res.status().as_u16() != 200 {
            //debug!("GET {} -> {}", &req_url.as_str(), res.status());
            return Err(Error::InvalidResponseStatus(res.status()));
        }

        match res.json::<EntriesResponse>() {
            Ok(j) => Ok(j
                .entries
                .iter()
                .map(|entry| CTEntry {
                    leaf_input: openssl::base64::decode_block(&entry.leaf_input).unwrap(),
                    extra_data: openssl::base64::decode_block(&entry.extra_data).unwrap(),
                })
                .collect()),
            Err(e) => {
                println!("error parsing json: {:?}", e);
                Err(Error::Unknown("error parsing json".to_owned()))
            }
        }
    }
}

fn new_http_client() -> Result<reqwest::blocking::Client, Error> {
    use std::time;
    let mut def_headers = reqwest::header::HeaderMap::new();
    def_headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static("certglass"),
    );
    match reqwest::blocking::Client::builder()
        .connect_timeout(time::Duration::from_secs(5))
        .gzip(true)
        .default_headers(def_headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(r) => Ok(r),
        Err(e) => Err(Error::Unknown(format!("{}", &e))),
    }
}
