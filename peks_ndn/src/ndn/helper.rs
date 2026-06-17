#[derive(Debug)]
pub enum NameParseError {
    Empty,
    MissingLeadingSlash,
}


pub fn parse_name(name: &str) -> Result<Vec<&str>, NameParseError> {
    // Reject empty inputs
    if name.is_empty() {
        return Err(NameParseError::Empty);
    }
    // Reject input without leading slash
    if !name.starts_with('/') {
        return Err(NameParseError::MissingLeadingSlash);
    }
    // Split on '/'
    let components: Vec<&str> = name.split('/').skip(1).collect();
    // Reject empty components from double slashes
    let non_empty_components: Vec<&str> = components.into_iter().filter(|s| !s.is_empty()).collect();
    // Return Vec of non-empty components
    if non_empty_components.is_empty() {
        return Err(NameParseError::Empty);
    }
    Ok(non_empty_components)
}


#[cfg(test)]
mod helper_name_parse_test {
    use super::*;

    #[test]
    fn parse_name_valid() {
        let name = "/ndn/peks/test";
        let components = parse_name(name).unwrap();
        assert_eq!(components, vec!["ndn", "peks", "test"]);
    }

    #[test]
    fn parse_name_empty() {
        let name = "";
        let result = parse_name(name);
        assert!(matches!(result, Err(NameParseError::Empty)));
    }

    #[test]
    fn parse_name_missing_leading_slash() {
        let name = "ndn/peks/test";
        let result = parse_name(name);
        assert!(matches!(result, Err(NameParseError::MissingLeadingSlash)));
    }

    #[test]
    fn parse_name_empty_component() {
        let name = "/ndn//test";
        let components = parse_name(name).unwrap();
        assert_eq!(components, vec!["ndn", "test"]);
    }
    #[test]
    fn parse_name_just_slashes_is_empty() {
        assert!(matches!(parse_name("/"), Err(NameParseError::Empty)));
        assert!(matches!(parse_name("//"), Err(NameParseError::Empty)));
    }
}