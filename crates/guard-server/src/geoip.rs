//! Offline, immutable MaxMind readers. Paths are startup configuration, never API input.
use maxminddb::{Reader, geoip2};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
};
const MAX_BYTES: u64 = 128 * 1024 * 1024;
#[derive(Clone, Default)]
pub(crate) struct GeoPaths {
    pub country: Option<PathBuf>,
    pub asn: Option<PathBuf>,
}
#[derive(Default)]
pub(crate) struct GeoCatalog {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    status: GeoStatus,
}
#[derive(Clone, Default, Serialize)]
pub(crate) struct GeoStatus {
    pub country: Option<DatabaseStatus>,
    pub asn: Option<DatabaseStatus>,
}
#[derive(Clone, Serialize)]
pub(crate) struct DatabaseStatus {
    pub database_type: String,
    pub build_epoch: u64,
    pub bytes: usize,
}
#[derive(Default, Serialize)]
pub(crate) struct GeoLookup {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub timezone: Option<String>,
    pub accuracy_radius_km: Option<u16>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
}
#[derive(Default, Deserialize)]
struct CountryCode<'a> {
    #[serde(borrow, default)]
    country: Country<'a>,
}
#[derive(Default, Deserialize)]
struct Country<'a> {
    #[serde(borrow, default)]
    iso_code: Option<&'a str>,
}
#[derive(Default, Deserialize)]
struct Asn {
    autonomous_system_number: Option<u32>,
}
fn valid_country(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn read(path: &Path, asn: bool) -> anyhow::Result<(Reader<Vec<u8>>, DatabaseStatus)> {
    let file_metadata = std::fs::metadata(path)
        .map_err(|_| anyhow::anyhow!("configured GeoIP database cannot be inspected"))?;
    anyhow::ensure!(
        file_metadata.is_file(),
        "GeoIP database must be a regular file"
    );
    let file = std::fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("configured GeoIP database cannot be opened"))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "GeoIP database must be a regular file"
    );
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_BYTES,
        "GeoIP database exceeds 128 MiB"
    );
    let mut data = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut data)?;
    anyhow::ensure!(
        data.len() as u64 <= MAX_BYTES,
        "GeoIP database exceeds 128 MiB"
    );
    let bytes = data.len();
    let reader =
        Reader::from_source(data).map_err(|_| anyhow::anyhow!("invalid GeoIP database"))?;
    reader
        .verify()
        .map_err(|_| anyhow::anyhow!("GeoIP database verification failed"))?;
    let metadata = reader.metadata();
    anyhow::ensure!(
        metadata.build_epoch <= crate::now().saturating_add(300),
        "GeoIP build time is in the future"
    );
    let supported = if asn {
        matches!(
            metadata.database_type.as_str(),
            "GeoIP2-ASN" | "GeoLite2-ASN"
        )
    } else {
        matches!(
            metadata.database_type.as_str(),
            "GeoIP2-Country"
                | "GeoLite2-Country"
                | "GeoIP2-City"
                | "GeoLite2-City"
                | "DBIP-Country-Lite"
        )
    };
    anyhow::ensure!(supported, "unsupported GeoIP database type");
    let status = DatabaseStatus {
        database_type: metadata.database_type.clone(),
        build_epoch: metadata.build_epoch,
        bytes,
    };
    Ok((reader, status))
}
impl GeoCatalog {
    pub fn load(paths: &GeoPaths) -> anyhow::Result<Self> {
        let mut catalog = Self::default();
        if let Some(path) = &paths.country {
            let (reader, status) = read(path, false)?;
            catalog.country = Some(reader);
            catalog.status.country = Some(status);
        }
        if let Some(path) = &paths.asn {
            let (reader, status) = read(path, true)?;
            catalog.asn = Some(reader);
            catalog.status.asn = Some(status);
        }
        Ok(catalog)
    }
    pub fn status(&self) -> GeoStatus {
        self.status.clone()
    }
    /// Decode only the two policy fields, avoiding city/name allocations on admission.
    pub fn context(&self, ip: IpAddr) -> guard_core::GeoContext<'_> {
        let ip = normalize(ip);
        let country = self
            .country
            .as_ref()
            .and_then(|r| r.lookup(ip).ok())
            .and_then(|r| r.decode::<CountryCode<'_>>().ok().flatten())
            .and_then(|c| c.country.iso_code)
            .filter(|code| valid_country(code));
        let asn = self
            .asn
            .as_ref()
            .and_then(|r| r.lookup(ip).ok())
            .and_then(|r| r.decode::<Asn>().ok().flatten())
            .and_then(|a| a.autonomous_system_number);
        guard_core::GeoContext { country, asn }
    }
    pub fn lookup(&self, ip: IpAddr) -> GeoLookup {
        let ip = normalize(ip);
        let mut out = GeoLookup::default();
        if let Some(r) = &self.country
            && let Ok(result) = r.lookup(ip)
            && let Ok(Some(city)) = result.decode::<geoip2::City<'_>>()
        {
            out.country_code = city
                .country
                .iso_code
                .filter(|code| valid_country(code))
                .map(str::to_owned);
            out.country_name = city.country.names.english.map(str::to_owned);
            out.city = city.city.names.english.map(str::to_owned);
            out.timezone = city.location.time_zone.map(str::to_owned);
            out.accuracy_radius_km = city.location.accuracy_radius;
            out.latitude = city.location.latitude;
            out.longitude = city.location.longitude;
        }
        if let Some(r) = &self.asn
            && let Ok(result) = r.lookup(ip)
            && let Ok(Some(asn)) = result.decode::<geoip2::Asn<'_>>()
        {
            out.asn = asn.autonomous_system_number;
            out.asn_organization = asn.autonomous_system_organization.map(str::to_owned);
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_country_and_city() {
        for (file, city) in [
            ("GeoIP2-Country-Test.mmdb", false),
            ("GeoIP2-City-Test.mmdb", true),
        ] {
            let catalog = GeoCatalog::load(&GeoPaths {
                country: Some(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("fixtures")
                        .join(file),
                ),
                asn: None,
            })
            .unwrap();
            let ip = "81.2.69.160".parse().unwrap();
            let result = catalog.lookup(ip);
            assert_eq!(result.country_code.as_deref(), Some("GB"));
            assert_eq!(catalog.context(ip).country, Some("GB"));
            if city {
                assert_eq!(result.city.as_deref(), Some("London"));
                assert_eq!(result.timezone.as_deref(), Some("Europe/London"));
            }
            assert!(
                catalog
                    .lookup("192.0.2.1".parse().unwrap())
                    .country_code
                    .is_none()
            );
        }
    }
    #[test]
    fn rejects_wrong_database_role() {
        assert!(
            GeoCatalog::load(&GeoPaths {
                country: None,
                asn: Some(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/GeoIP2-Country-Test.mmdb")
                )
            })
            .is_err()
        );
    }
}
