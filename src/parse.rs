use log::trace;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while_m_n},
    character::complete::{alphanumeric1, multispace1},
    combinator::{recognize, verify},
    multi::{many0_count, many1_count},
    sequence::{pair, tuple},
    IResult,
};
use std::collections::HashSet;
use url::Host;

fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn parse_ipv4_octet(input: &str) -> IResult<&str, &str> {
    verify(take_while_m_n(1, 3, is_digit), |val: &str| {
        val.parse::<u8>().is_ok()
    })(input)
}

fn parse_hostname_element(input: &str) -> IResult<&str, &str> {
    verify(
        recognize(many1_count(alt((alphanumeric1, tag("-"), tag("_"))))),
        |val: &str| val.len() <= 63,
    )(input)
}

fn parse_hostname(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        recognize(many1_count(pair(parse_hostname_element, tag(".")))),
        parse_hostname_element,
    )))(input)
}

fn parse_ipv4_address(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        verify(
            many0_count(pair(parse_ipv4_octet, tag("."))),
            |val: &usize| *val <= 3,
        ),
        parse_ipv4_octet,
    ))(input)
}

fn parse_domainlist_line(input: &str) -> Option<&str> {
    // expect "example.com"
    let Ok((_rest, hostname)) = parse_hostname(input) else {
        return None;
    };
    Some(hostname)
}

fn parse_hostfile_line(input: &str) -> Option<&str> {
    // expect "127.0.0.1 example.com"
    let Ok((_rest, (_ipv4_address, _, hostname))) =
        tuple((parse_ipv4_address, multispace1, parse_hostname))(input)
    else {
        return None;
    };
    Some(hostname)
}

pub fn domainlist(file_body: &str, set: &mut HashSet<Host>) {
    for line in file_body.lines() {
        if let Some(value) = parse_domainlist_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                trace!("Unable to parse hostname in line `{value}`");
            }
        } else if !line.is_empty() && line.trim_start()[0..1] != *"#" {
            trace!("Unable to parse `{line}`");
        }
    }
}

pub fn hostfile(file_body: &str, set: &mut HashSet<Host>) {
    for line in file_body.lines() {
        if let Some(value) = parse_hostfile_line(line) {
            if let Ok(host_value) = Host::parse(value) {
                set.insert(host_value);
            } else {
                trace!("Unable to parse hostname in line `{value}`");
            }
        } else if !line.is_empty() && line.trim_start()[0..1] != *"#" {
            trace!("Unable to parse `{line}`");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_hostfile_line, parse_hostname, parse_ipv4_address, parse_ipv4_octet};
    use fake::{faker, Fake};

    #[test]
    fn parse_ip4_octet_parses_valid_ipv4_octet() {
        // arrange
        let input_0: &str = "1";
        let input_1: &str = "12";
        let input_2: &str = "123";
        let input_3: &str = "1234";

        // act
        let result_0 = parse_ipv4_octet(input_0);
        let result_1 = parse_ipv4_octet(input_1);
        let result_2 = parse_ipv4_octet(input_2);
        let result_3 = parse_ipv4_octet(input_3);

        // assert
        assert_eq!(result_0, Ok(("", "1")));
        assert_eq!(result_1, Ok(("", "12")));
        assert_eq!(result_2, Ok(("", "123")));
        assert_eq!(result_3, Ok(("4", "123")));
    }

    #[test]
    fn parse_ipv4_octet_fails_to_parse_invalid_ipv4_octet() {
        // arrange
        let input_0: &str = "";
        let input_1: &str = ".";
        let input_2: &str = "256";

        // act
        let result_0 = parse_ipv4_octet(input_0);
        let result_1 = parse_ipv4_octet(input_1);
        let result_2 = parse_ipv4_octet(input_2);

        // assert
        assert_eq!(
            result_0,
            Err(nom::Err::Error(nom::error::Error {
                input: "",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
        assert_eq!(
            result_1,
            Err(nom::Err::Error(nom::error::Error {
                input: ".",
                code: nom::error::ErrorKind::TakeWhileMN
            }))
        );
        assert_eq!(
            result_2,
            Err(nom::Err::Error(nom::error::Error {
                input: "256",
                code: nom::error::ErrorKind::Verify
            }))
        );
    }

    #[derive(Debug, Clone)]
    struct ValidIPv4AddressFixture(pub String);

    impl quickcheck::Arbitrary for ValidIPv4AddressFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let ipv4_address = faker::internet::en::IPv4().fake_with_rng(g);
            Self(ipv4_address)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn parse_ipv4_address_parses_random_generated_ipv4_address(
        valid_ipv4_address: ValidIPv4AddressFixture,
    ) -> bool {
        parse_ipv4_address(&valid_ipv4_address.0).is_ok()
    }

    #[test]
    fn parse_ipv4_address_parses_valid_ipv4_address() {
        // arrange
        let input_0: &str = "127.0.0.1";
        let input_1: &str = "127";
        let input_2: &str = "127.0.0.1 example.com";

        // act
        let result_0 = parse_ipv4_address(input_0);
        let result_1 = parse_ipv4_address(input_1);
        let result_2 = parse_ipv4_address(input_2);

        // assert
        assert_eq!(result_0, Ok(("", "127.0.0.1")));
        assert_eq!(result_1, Ok(("", "127")));
        assert_eq!(result_2, Ok((" example.com", "127.0.0.1")));
    }

    #[test]
    fn parse_ipv4_address_fails_to_parse_invalid_ipv4_address() {
        // arrange
        let input_0: &str = "127.0.0.1.1";

        // act
        let result_0 = parse_ipv4_address(input_0);

        // assert
        assert_eq!(
            result_0,
            Err(nom::Err::Error(nom::error::Error {
                input: "127.0.0.1.1",
                code: nom::error::ErrorKind::Verify
            }))
        );
    }

    #[derive(Debug, Clone)]
    struct ValidHostnameFixture(pub String);

    // TODO add domains with hyphens
    impl quickcheck::Arbitrary for ValidHostnameFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let subdomains: Vec<String> = faker::lorem::en::Words(1..3).fake_with_rng(g);
            let domain_suffix = faker::internet::en::DomainSuffix().fake_with_rng(g);
            let mut hostname = subdomains.iter().fold(String::new(), |mut acc, x| {
                acc.push_str(x);
                acc.push('.');
                acc
            });
            hostname.push_str(domain_suffix);
            Self(hostname)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn parse_hostname_address_parses_random_generated_hostname(
        valid_hostname: ValidHostnameFixture,
    ) -> bool {
        parse_hostname(&valid_hostname.0).is_ok()
    }

    #[test]
    fn parse_hostname_parses_valid_hostnames() {
        // arrange
        let input_0: &str = "example.com";
        let input_1: &str = "sub.example.com";
        let input_2: &str = "sub-domain.example.com";
        let input_3: &str = "sub_domain.example.com";

        // act
        let result_0 = parse_hostname(input_0);
        let result_1 = parse_hostname(input_1);
        let result_2 = parse_hostname(input_2);
        let result_3 = parse_hostname(input_3);

        // assert
        assert_eq!(result_0, Ok(("", "example.com")));
        assert_eq!(result_1, Ok(("", "sub.example.com")));
        assert_eq!(result_2, Ok(("", "sub-domain.example.com")));
        assert_eq!(result_3, Ok(("", "sub_domain.example.com")));
    }

    #[test]
    fn parse_hostfile_line_successfully_parses_valid_input() {
        // arrange
        let input_0: &str = "127.0.0.1 example.com";

        // act
        let result_0 = parse_hostfile_line(input_0);

        // assert
        assert_eq!(result_0, Some("example.com"));
    }
}
