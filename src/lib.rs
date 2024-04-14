use hmac::{Hmac, Mac};
use http::header::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::OffsetDateTime;
use url::Url;

#[derive(Debug)]
pub struct AwsSign<'a, T: 'a>
where
    &'a T: std::iter::IntoIterator<Item = (&'a String, &'a String)>,
{
    method: &'a str,
    url: Url,
    datetime: &'a OffsetDateTime,
    region: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    headers: T,

    /* 
    service is the <aws-service-code> that can be found in the service-quotas api.
    
    For example, use the value `ServiceCode` for this `service` property.
    Thus, for "Amazon Simple Storage Service (Amazon S3)", you would use value "s3"

    ```
    > aws service-quotas list-services
    {
        "Services": [
            ...
            {
                "ServiceCode": "a4b",
                "ServiceName": "Alexa for Business"
            },
            ...
            {
                "ServiceCode": "s3",
                "ServiceName": "Amazon Simple Storage Service (Amazon S3)"
            },
            ...
    ```
    This is not absolute, so you might need to poke around at the service you're interesed in.
    See:
    [AWS General Reference -> Service endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/aws-service-information.html) - to look up "service" names and codes

    added in 0.2.0
    */
    service: &'a str,

    /// body, such as in an http POST
    body: &'a [u8],
}

impl<'a> AwsSign<'a, HashMap<String, String>> {
    pub fn new<B: AsRef<[u8]> + ?Sized>(
        method: &'a str,
        url: &'a str,
        datetime: &'a OffsetDateTime,
        headers: &'a HeaderMap,
        region: &'a str,
        access_key: &'a str,
        secret_key: &'a str,
        service: &'a str,
        body: &'a B,
    ) -> Self {
        let url: Url = url.parse().unwrap();
        let headers: HashMap<String, String> = headers
            .iter()
            .filter_map(|(key, value)| {
                if let Ok(value_inner) = value.to_str() {
                    Some((key.as_str().to_owned(), value_inner.to_owned()))
                } else {
                    None
                }
            })
            .collect();
        Self {
            method,
            url,
            datetime,
            region,
            access_key,
            secret_key,
            headers,
            service,
            body: body.as_ref(),
        }
    }
}

impl<'a, T> AwsSign<'a, T>
where
    &'a T: std::iter::IntoIterator<Item = (&'a String, &'a String)>,
{
    //Thanks https://github.com/durch/rust-s3 for the signing implementation.

    pub fn canonical_header_string(&'a self) -> String {
        let mut keyvalues = self
            .headers
            .into_iter()
            .map(|(key, value)| key.to_lowercase() + ":" + value.trim())
            .collect::<Vec<String>>();
        keyvalues.sort();
        keyvalues.join("\n")
    }

    pub fn signed_header_string(&'a self) -> String {
        let mut keys = self
            .headers
            .into_iter()
            .map(|(key, _)| key.to_lowercase())
            .collect::<Vec<String>>();
        keys.sort();
        keys.join(";")
    }

    pub fn canonical_request(&'a self) -> String {
        let url: &str = self.url.path().into();

        format!(
            "{method}\n{uri}\n{query_string}\n{headers}\n\n{signed}\n{sha256}",
            method = self.method,
            uri = url,
            query_string = canonical_query_string(&self.url),
            headers = self.canonical_header_string(),
            signed = self.signed_header_string(),
            sha256 = digest(self.body),
        )
    }
    pub fn sign(&'a self) -> String {
        let canonical = self.canonical_request();
        let string_to_sign = string_to_sign(self.datetime, self.region, &canonical, self.service);
        let signing_key = signing_key(self.datetime, self.secret_key, self.region, self.service).unwrap();
        let signature = hex::encode(hmac_sha256(signing_key, string_to_sign).unwrap());
        let signed_headers = self.signed_header_string();

        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope},\
             SignedHeaders={signed_headers},Signature={signature}",
            access_key = self.access_key,
            scope = scope_string(self.datetime, self.region, self.service),
            signed_headers = signed_headers,
            signature = signature
        )
    }
}

pub fn uri_encode(string: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(string.len() * 2);
    for c in string.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '~' | '.' => result.push(c),
            '/' if encode_slash => result.push_str("%2F"),
            '/' if !encode_slash => result.push('/'),
            _ => {
                result.push('%');
                result.push_str(
                    &format!("{}", c)
                        .bytes()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>(),
                );
            }
        }
    }
    result
}

pub fn canonical_query_string(uri: &Url) -> String {
    let mut keyvalues = uri
        .query_pairs()
        .map(|(key, value)| uri_encode(&key, true) + "=" + &uri_encode(&value, true))
        .collect::<Vec<String>>();
    keyvalues.sort();
    keyvalues.join("&")
}

pub fn scope_string(datetime: &OffsetDateTime, region: &str, service: &str) -> String {
    format!(
        "{date}/{region}/{service}/aws4_request",
        date = format_as_short_date(datetime),
        region = region,
        service = service
    )
}

pub fn string_to_sign(datetime: &OffsetDateTime, region: &str, canonical_req: &str, service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{hash}",
        timestamp = format_as_long_datetime(datetime),
        scope = scope_string(datetime, region, service),
        hash = digest(canonical_req.as_bytes())
    )
}

pub fn signing_key(
    datetime: &OffsetDateTime,
    secret_key: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, String> {
    let secret = String::from("AWS4") + secret_key;

    let date_key = hmac_sha256(secret.as_bytes(), format_as_short_date(datetime).as_bytes())?;
    let region_key = hmac_sha256(date_key, region.to_string().as_bytes())?;
    let service_key = hmac_sha256(region_key, service.as_bytes())?;
    hmac_sha256(service_key, b"aws4_request")
}

fn hmac_sha256(key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_ref()).map_err(|e| e.to_string())?;
    hmac.update(value.as_ref());
    Ok(hmac.finalize().into_bytes().to_vec())
}

fn digest(input: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(input).as_slice())
}

const SHORT_DATE: &[BorrowedFormatItem] = format_description!("[year][month][day]");
const LONG_DATETIME: &[BorrowedFormatItem] = format_description!("[year][month][day]T[hour][minute][second]Z");

fn format_as_short_date(datetime: &OffsetDateTime) -> String {
    datetime.format(&SHORT_DATE).unwrap()
}

fn format_as_long_datetime(datetime: &OffsetDateTime) -> String {
    datetime.format(&LONG_DATETIME).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_canonical_request() {
        let datetime = time::OffsetDateTime::now_utc();
        let url: &str = "https://hi.s3.us-east-1.amazonaws.com/Prod/graphql";
        let map: HeaderMap = HeaderMap::new();
        let aws_sign = AwsSign::new(
            "GET", 
            url, 
            &datetime, 
            &map, 
            "us-east-1", 
            "a", 
            "b", 
            "s3", 
            ""
        );
        let s = aws_sign.canonical_request();
        assert_eq!(s, "GET\n/Prod/graphql\n\n\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sample_canonical_request_using_u8_body() {
        let datetime = OffsetDateTime::now_utc();
        let url: &str = "https://hi.s3.us-east-1.amazonaws.com/Prod/graphql";
        let map: HeaderMap = HeaderMap::new();
        let aws_sign = AwsSign::new(
            "GET",
            url,
            &datetime,
            &map,
            "us-east-1",
            "a",
            "b",
            "s3",
            "".as_bytes(),
        );
        let s = aws_sign.canonical_request();
        assert_eq!(s, "GET\n/Prod/graphql\n\n\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sample_canonical_request_using_vec_body() {
        let datetime = OffsetDateTime::now_utc();
        let url: &str = "https://hi.s3.us-east-1.amazonaws.com/Prod/graphql";
        let map: HeaderMap = HeaderMap::new();
        let body = Vec::new();
        let aws_sign = AwsSign::new(
            "GET",
            url,
            &datetime,
            &map,
            "us-east-1",
            "a",
            "b",
            "s3",
            &body,
        );
        let s = aws_sign.canonical_request();
        assert_eq!(s, "GET\n/Prod/graphql\n\n\n\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
