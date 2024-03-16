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
    use proptest::{prop_assert_eq, prop_compose, proptest};

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

    proptest! {
    #[test]
    fn parse_ip4_octet_parses_valid_ipv4_octet_proptest(octet in 0u8..) {
        // arrange
        let octet_string = octet.to_string();

        // act
        let result = parse_ipv4_octet(&octet_string);

        // assert
        prop_assert_eq!(result, Ok(("", octet_string.as_str())));
    }
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

    proptest! {
    #[test]
    fn parse_ipv4_adress_parses_valid_ipv4_proptest(
        octet_0 in 0u8..,
        octet_1 in 0u8..,
        octet_2 in 0u8..,
        octet_3 in 0u8..) {
        // arrange
        let ipv4_address = format!("{octet_0}.{octet_1}.{octet_2}.{octet_3}");

        // act
        let result = parse_ipv4_address(&ipv4_address);

        // assert
        prop_assert_eq!(result, Ok(("", ipv4_address.as_str())));
    }
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

    prop_compose! {
        fn valid_domain()(
            subdomain_0 in "[a-zA-Z0-9_-]{1,63}",
            subdomain_1 in "[a-zA-Z0-9_-]{1,63}",
            subdomain_2 in "[a-zA-Z0-9_-]{1,63}",
            subdomains in 1u8..4
        ) -> String {
        // valid domain can be up to (and including) 253 characters
        match subdomains {
            1 =>  format!("{subdomain_0}.com"),
            2 =>  format!("{subdomain_0}.{subdomain_1}.com"),
            3 =>  format!("{subdomain_0}.{subdomain_1}.{subdomain_2}.com"),
            _ => unreachable!("Unexpected subdomain count")
        }
        }
    }

    proptest! {
         #[test]
         fn parse_hostname_parses_valid_hostnames_proptest(
    hostname in valid_domain())
     {
             // arrange
             // act
             let result = parse_hostname(&hostname);

             // assert
             prop_assert_eq!(result, Ok(("", hostname.as_str())));
         }
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
