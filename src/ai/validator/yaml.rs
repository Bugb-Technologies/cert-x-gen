//! YAML-specific template validation
//!
//! This module validates YAML templates for the Nuclei-compatible format.
//! It checks:
//! - Required fields (id, name, author, severity, etc.)
//! - Execution blocks (http, network, flows)
//! - Matcher types and configuration
//! - Extractor configuration
//! - Variable references
//! - Port and protocol validation

use super::TemplateDiagnostic;
use anyhow::Result;

/// Valid matcher types
const VALID_MATCHER_TYPES: &[&str] = &[
    "word",
    "regex", 
    "binary",
    "status",
    "size",
    "dsl",
    "xpath",
];

/// Valid extractor types
const VALID_EXTRACTOR_TYPES: &[&str] = &[
    "regex",
    "kval",
    "xpath",
    "json",
    "dsl",
];

/// Valid HTTP methods
const VALID_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Valid matcher conditions
const VALID_MATCHER_CONDITIONS: &[&str] = &["and", "or"];

pub fn validate(code: &str) -> Result<Vec<TemplateDiagnostic>> {
    let mut diagnostics = Vec::new();

    // Parse YAML to check syntax
    let yaml: serde_yaml::Value = match serde_yaml::from_str(code) {
        Ok(v) => v,
        Err(e) => {
            return Ok(vec![TemplateDiagnostic::error(
                "yaml.syntax_error",
                format!("Invalid YAML syntax: {}", e),
            )]);
        }
    };

    // Top-level document must be a mapping
    let yaml_map = match yaml.as_mapping() {
        Some(m) => m,
        None => {
            return Ok(vec![TemplateDiagnostic::error(
                "yaml.not_mapping",
                "YAML template must be a mapping/object",
            )]);
        }
    };

    // Required fields
    diagnostics.extend(validate_required_fields(yaml_map, code));

    // Validate author structure
    diagnostics.extend(validate_author(yaml_map));

    // Validate severity
    diagnostics.extend(validate_severity(yaml_map));

    // Validate language field
    diagnostics.extend(validate_language(yaml_map));

    // Must have at least one execution block
    diagnostics.extend(validate_execution_blocks(yaml_map, code));

    // Validate HTTP section if present
    if let Some(http) = yaml_map.get("http") {
        diagnostics.extend(validate_http_section(http, code));
    }

    // Validate network section if present
    if let Some(network) = yaml_map.get("network") {
        diagnostics.extend(validate_network_section(network, code));
    }

    // Validate matchers at top level or in requests
    diagnostics.extend(validate_matchers_in_document(yaml_map, code));

    // Validate extractors at top level or in requests
    diagnostics.extend(validate_extractors_in_document(yaml_map, code));

    // Validate variable references
    diagnostics.extend(validate_variable_references(code));

    Ok(diagnostics)
}

/// Validate required fields
fn validate_required_fields(yaml_map: &serde_yaml::Mapping, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let required_fields = vec!["id", "name", "author", "severity", "description", "language"];
    for field in required_fields {
        if !yaml_map.contains_key(field) {
            let line = find_yaml_field_line(code, "id").unwrap_or(1);
            diagnostics.push(
                TemplateDiagnostic::error(
                    format!("yaml.missing_{}", field),
                    format!("YAML template missing required field: '{}'", field),
                )
                .with_location(line, None)
            );
        }
    }
    
    diagnostics
}

/// Validate author structure
fn validate_author(yaml_map: &serde_yaml::Mapping) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    if let Some(author) = yaml_map.get("author") {
        if let Some(author_map) = author.as_mapping() {
            if !author_map.contains_key("name") {
                diagnostics.push(TemplateDiagnostic::error(
                    "yaml.missing_author_name",
                    "'author' field must have a 'name' sub-field",
                ));
            }
        } else if !author.is_string() {
            diagnostics.push(TemplateDiagnostic::error(
                "yaml.author_not_mapping",
                "'author' field must be a mapping or string",
            ));
        }
    }
    
    diagnostics
}

/// Validate severity value
fn validate_severity(yaml_map: &serde_yaml::Mapping) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    if let Some(severity) = yaml_map.get("severity").and_then(|v| v.as_str()) {
        let valid = vec!["critical", "high", "medium", "low", "info", "informational"];
        if !valid.contains(&severity.to_lowercase().as_str()) {
            diagnostics.push(TemplateDiagnostic::error(
                "yaml.invalid_severity",
                format!("Invalid severity '{}'. Must be one of: critical, high, medium, low, info", severity),
            ));
        }
    }
    
    diagnostics
}

/// Validate language field
fn validate_language(yaml_map: &serde_yaml::Mapping) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    if let Some(language) = yaml_map.get("language").and_then(|v| v.as_str()) {
        if language.to_lowercase() != "yaml" {
            diagnostics.push(TemplateDiagnostic::error(
                "yaml.invalid_language",
                format!("YAML template 'language' field must be 'yaml', found '{}'", language),
            ));
        }
    }
    
    diagnostics
}

/// Validate execution blocks exist
fn validate_execution_blocks(yaml_map: &serde_yaml::Mapping, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let has_http = yaml_map.contains_key("http") || yaml_map.contains_key("requests");
    let has_network = yaml_map.contains_key("network") || yaml_map.contains_key("tcp") || yaml_map.contains_key("udp");
    let has_flows = yaml_map.contains_key("flows") || yaml_map.contains_key("workflow");
    let has_dns = yaml_map.contains_key("dns");
    
    if !has_http && !has_network && !has_flows && !has_dns {
        let line = find_yaml_field_line(code, "id").unwrap_or(1);
        diagnostics.push(
            TemplateDiagnostic::error(
                "yaml.no_execution_block",
                "YAML template must have at least one of: 'http', 'network', 'dns', or 'flows' sections",
            )
            .with_location(line, None)
        );
    }
    
    diagnostics
}

/// Validate HTTP section
fn validate_http_section(http: &serde_yaml::Value, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let http_items = if let Some(seq) = http.as_sequence() {
        seq.clone()
    } else if http.is_mapping() {
        vec![http.clone()]
    } else {
        return vec![TemplateDiagnostic::error(
            "yaml.http_invalid_type",
            "'http' section must be a sequence or mapping",
        )];
    };

    for (idx, item) in http_items.iter().enumerate() {
        if let Some(item_map) = item.as_mapping() {
            // Validate HTTP method
            if let Some(method) = item_map.get("method").and_then(|v| v.as_str()) {
                if !VALID_HTTP_METHODS.contains(&method.to_uppercase().as_str()) {
                    let line = find_yaml_field_line(code, "method");
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.invalid_http_method",
                            format!(
                                "http[{}]: Unknown HTTP method '{}'. Valid: {}",
                                idx, method, VALID_HTTP_METHODS.join(", ")
                            ),
                        )
                        .with_location(line.unwrap_or(1), None)
                    );
                }
            }

            // Validate path exists
            if !item_map.contains_key("path") && !item_map.contains_key("raw") {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "yaml.http_missing_path",
                        format!("http[{}]: Should have 'path' or 'raw' field", idx),
                    )
                );
            }

            // Validate matchers in HTTP item
            if let Some(matchers) = item_map.get("matchers") {
                diagnostics.extend(validate_matchers(matchers, code, &format!("http[{}]", idx)));
            }

            // Validate matchers-condition
            if let Some(cond) = item_map.get("matchers-condition").and_then(|v| v.as_str()) {
                if !VALID_MATCHER_CONDITIONS.contains(&cond.to_lowercase().as_str()) {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.invalid_matchers_condition",
                            format!(
                                "http[{}]: Invalid matchers-condition '{}'. Valid: and, or",
                                idx, cond
                            ),
                        )
                    );
                }
            }

            // Validate extractors in HTTP item
            if let Some(extractors) = item_map.get("extractors") {
                diagnostics.extend(validate_extractors(extractors, code, &format!("http[{}]", idx)));
            }
        }
    }
    
    diagnostics
}

/// Validate network section
fn validate_network_section(network: &serde_yaml::Value, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let network_items = if let Some(seq) = network.as_sequence() {
        seq.clone()
    } else if network.is_mapping() {
        vec![network.clone()]
    } else {
        return vec![TemplateDiagnostic::error(
            "yaml.network_invalid_type",
            "'network' section must be a sequence or mapping",
        )];
    };

    for (idx, item) in network_items.iter().enumerate() {
        if let Some(item_map) = item.as_mapping() {
            // Validate port
            if let Some(port) = item_map.get("port") {
                if let Some(port_num) = port.as_u64() {
                    if port_num == 0 || port_num > 65535 {
                        let line = find_yaml_field_line(code, "port");
                        diagnostics.push(
                            TemplateDiagnostic::error(
                                "yaml.invalid_port",
                                format!(
                                    "network[{}]: Invalid port {}. Must be 1-65535",
                                    idx, port_num
                                ),
                            )
                            .with_location(line.unwrap_or(1), None)
                        );
                    }
                } else if port.as_str().map(|s| s.starts_with("{{")).unwrap_or(false) {
                    // Port is a variable reference, that's okay
                } else {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.port_not_number",
                            format!("network[{}]: 'port' should be a number or variable reference", idx),
                        )
                    );
                }
            } else {
                diagnostics.push(
                    TemplateDiagnostic::warning(
                        "yaml.network_missing_port",
                        format!("network[{}]: Should have a 'port' field", idx),
                    )
                );
            }

            // Validate payloads structure
            if let Some(payloads) = item_map.get("payloads") {
                if !payloads.is_sequence() {
                    let line = find_yaml_field_line(code, "payloads");
                    diagnostics.push(
                        TemplateDiagnostic::error(
                            "yaml.invalid_payloads_type",
                            format!(
                                "network[{}].payloads must be a sequence (list), not a map. \
                                 Fix: Change from 'payloads: {{key: [...]}}' to 'payloads: [...]'",
                                idx
                            ),
                        )
                        .with_location(line.unwrap_or(1), None)
                    );
                }
            }

            // Validate inputs (alternative to payloads)
            if let Some(inputs) = item_map.get("inputs") {
                if let Some(inputs_seq) = inputs.as_sequence() {
                    for (input_idx, input) in inputs_seq.iter().enumerate() {
                        if let Some(input_map) = input.as_mapping() {
                            if !input_map.contains_key("data") && !input_map.contains_key("read") {
                                diagnostics.push(
                                    TemplateDiagnostic::warning(
                                        "yaml.input_missing_data",
                                        format!(
                                            "network[{}].inputs[{}]: Should have 'data' or 'read' field",
                                            idx, input_idx
                                        ),
                                    )
                                );
                            }
                        }
                    }
                }
            }

            // Validate matchers in network item
            if let Some(matchers) = item_map.get("matchers") {
                diagnostics.extend(validate_matchers(matchers, code, &format!("network[{}]", idx)));
            }

            // Validate extractors in network item
            if let Some(extractors) = item_map.get("extractors") {
                diagnostics.extend(validate_extractors(extractors, code, &format!("network[{}]", idx)));
            }
        }
    }
    
    diagnostics
}

/// Validate matchers array
fn validate_matchers(matchers: &serde_yaml::Value, code: &str, context: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let matchers_seq = match matchers.as_sequence() {
        Some(seq) => seq,
        None => {
            return vec![TemplateDiagnostic::error(
                "yaml.matchers_not_sequence",
                format!("{}: 'matchers' must be a sequence (list)", context),
            )];
        }
    };

    for (idx, matcher) in matchers_seq.iter().enumerate() {
        if let Some(matcher_map) = matcher.as_mapping() {
            // Validate matcher type
            if let Some(matcher_type) = matcher_map.get("type").and_then(|v| v.as_str()) {
                if !VALID_MATCHER_TYPES.contains(&matcher_type.to_lowercase().as_str()) {
                    let line = find_yaml_field_line(code, "type");
                    diagnostics.push(
                        TemplateDiagnostic::error(
                            "yaml.invalid_matcher_type",
                            format!(
                                "{}.matchers[{}]: Invalid type '{}'. Valid: {}",
                                context, idx, matcher_type, VALID_MATCHER_TYPES.join(", ")
                            ),
                        )
                        .with_location(line.unwrap_or(1), None)
                    );
                }

                // Type-specific validation
                match matcher_type.to_lowercase().as_str() {
                    "word" => {
                        if !matcher_map.contains_key("words") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.matcher_word_missing_words",
                                    format!(
                                        "{}.matchers[{}]: 'word' matcher requires 'words' field",
                                        context, idx
                                    ),
                                )
                            );
                        } else if let Some(words) = matcher_map.get("words") {
                            if !words.is_sequence() {
                                diagnostics.push(
                                    TemplateDiagnostic::error(
                                        "yaml.matcher_words_not_sequence",
                                        format!(
                                            "{}.matchers[{}]: 'words' must be a list",
                                            context, idx
                                        ),
                                    )
                                );
                            }
                        }
                    }
                    "regex" => {
                        if !matcher_map.contains_key("regex") && !matcher_map.contains_key("part") {
                            diagnostics.push(
                                TemplateDiagnostic::warning(
                                    "yaml.matcher_regex_missing_pattern",
                                    format!(
                                        "{}.matchers[{}]: 'regex' matcher should have 'regex' field",
                                        context, idx
                                    ),
                                )
                            );
                        }
                        // Validate regex patterns compile
                        if let Some(regex_patterns) = matcher_map.get("regex").and_then(|v| v.as_sequence()) {
                            for (pat_idx, pattern) in regex_patterns.iter().enumerate() {
                                if let Some(pat_str) = pattern.as_str() {
                                    if let Err(e) = regex::Regex::new(pat_str) {
                                        diagnostics.push(
                                            TemplateDiagnostic::error(
                                                "yaml.invalid_regex_pattern",
                                                format!(
                                                    "{}.matchers[{}].regex[{}]: Invalid regex '{}': {}",
                                                    context, idx, pat_idx, pat_str, e
                                                ),
                                            )
                                        );
                                    }
                                }
                            }
                        }
                    }
                    "status" => {
                        if !matcher_map.contains_key("status") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.matcher_status_missing_codes",
                                    format!(
                                        "{}.matchers[{}]: 'status' matcher requires 'status' field with HTTP codes",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "binary" => {
                        if !matcher_map.contains_key("binary") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.matcher_binary_missing_data",
                                    format!(
                                        "{}.matchers[{}]: 'binary' matcher requires 'binary' field",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "dsl" => {
                        if !matcher_map.contains_key("dsl") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.matcher_dsl_missing_expression",
                                    format!(
                                        "{}.matchers[{}]: 'dsl' matcher requires 'dsl' field with expressions",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    _ => {}
                }
            } else {
                // No type specified - check for implicit type
                let has_words = matcher_map.contains_key("words");
                let has_regex = matcher_map.contains_key("regex");
                let has_status = matcher_map.contains_key("status");
                let has_binary = matcher_map.contains_key("binary");
                let has_dsl = matcher_map.contains_key("dsl");

                if !has_words && !has_regex && !has_status && !has_binary && !has_dsl {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.matcher_missing_type",
                            format!(
                                "{}.matchers[{}]: Matcher should have explicit 'type' field. Valid: {}",
                                context, idx, VALID_MATCHER_TYPES.join(", ")
                            ),
                        )
                    );
                }
            }

            // Validate condition field
            if let Some(condition) = matcher_map.get("condition").and_then(|v| v.as_str()) {
                if !VALID_MATCHER_CONDITIONS.contains(&condition.to_lowercase().as_str()) {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.invalid_matcher_condition",
                            format!(
                                "{}.matchers[{}]: Invalid condition '{}'. Valid: and, or",
                                context, idx, condition
                            ),
                        )
                    );
                }
            }

            // Validate part field if present
            if let Some(part) = matcher_map.get("part").and_then(|v| v.as_str()) {
                let valid_parts = ["body", "header", "all", "raw", "interactsh_protocol", "interactsh_request"];
                if !valid_parts.contains(&part.to_lowercase().as_str()) {
                    diagnostics.push(
                        TemplateDiagnostic::info(
                            "yaml.unusual_matcher_part",
                            format!(
                                "{}.matchers[{}]: Unusual part '{}'. Common: body, header, all",
                                context, idx, part
                            ),
                        )
                    );
                }
            }
        } else {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "yaml.matcher_not_mapping",
                    format!("{}.matchers[{}]: Each matcher must be a mapping", context, idx),
                )
            );
        }
    }
    
    diagnostics
}

/// Validate extractors array
fn validate_extractors(extractors: &serde_yaml::Value, code: &str, context: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    let extractors_seq = match extractors.as_sequence() {
        Some(seq) => seq,
        None => {
            return vec![TemplateDiagnostic::error(
                "yaml.extractors_not_sequence",
                format!("{}: 'extractors' must be a sequence (list)", context),
            )];
        }
    };

    for (idx, extractor) in extractors_seq.iter().enumerate() {
        if let Some(extractor_map) = extractor.as_mapping() {
            // Validate extractor type
            if let Some(extractor_type) = extractor_map.get("type").and_then(|v| v.as_str()) {
                if !VALID_EXTRACTOR_TYPES.contains(&extractor_type.to_lowercase().as_str()) {
                    let line = find_yaml_field_line(code, "type");
                    diagnostics.push(
                        TemplateDiagnostic::error(
                            "yaml.invalid_extractor_type",
                            format!(
                                "{}.extractors[{}]: Invalid type '{}'. Valid: {}",
                                context, idx, extractor_type, VALID_EXTRACTOR_TYPES.join(", ")
                            ),
                        )
                        .with_location(line.unwrap_or(1), None)
                    );
                }

                // Type-specific validation
                match extractor_type.to_lowercase().as_str() {
                    "regex" => {
                        if !extractor_map.contains_key("regex") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.extractor_regex_missing_pattern",
                                    format!(
                                        "{}.extractors[{}]: 'regex' extractor requires 'regex' field",
                                        context, idx
                                    ),
                                )
                            );
                        } else if let Some(regex_patterns) = extractor_map.get("regex").and_then(|v| v.as_sequence()) {
                            // Validate regex patterns compile
                            for (pat_idx, pattern) in regex_patterns.iter().enumerate() {
                                if let Some(pat_str) = pattern.as_str() {
                                    if let Err(e) = regex::Regex::new(pat_str) {
                                        diagnostics.push(
                                            TemplateDiagnostic::error(
                                                "yaml.invalid_extractor_regex",
                                                format!(
                                                    "{}.extractors[{}].regex[{}]: Invalid regex '{}': {}",
                                                    context, idx, pat_idx, pat_str, e
                                                ),
                                            )
                                        );
                                    }
                                }
                            }
                        }

                        // Check for group in regex extractor
                        if !extractor_map.contains_key("group") {
                            diagnostics.push(
                                TemplateDiagnostic::info(
                                    "yaml.extractor_regex_no_group",
                                    format!(
                                        "{}.extractors[{}]: Consider adding 'group' to specify capture group (default: 0)",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "kval" => {
                        if !extractor_map.contains_key("kval") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.extractor_kval_missing_keys",
                                    format!(
                                        "{}.extractors[{}]: 'kval' extractor requires 'kval' field with key names",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "json" => {
                        if !extractor_map.contains_key("json") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.extractor_json_missing_path",
                                    format!(
                                        "{}.extractors[{}]: 'json' extractor requires 'json' field with JSON path",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "xpath" => {
                        if !extractor_map.contains_key("xpath") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.extractor_xpath_missing_path",
                                    format!(
                                        "{}.extractors[{}]: 'xpath' extractor requires 'xpath' field",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    "dsl" => {
                        if !extractor_map.contains_key("dsl") {
                            diagnostics.push(
                                TemplateDiagnostic::error(
                                    "yaml.extractor_dsl_missing_expression",
                                    format!(
                                        "{}.extractors[{}]: 'dsl' extractor requires 'dsl' field",
                                        context, idx
                                    ),
                                )
                            );
                        }
                    }
                    _ => {}
                }
            } else {
                // No type - infer from fields
                let has_regex = extractor_map.contains_key("regex");
                let has_kval = extractor_map.contains_key("kval");
                let has_json = extractor_map.contains_key("json");
                let has_xpath = extractor_map.contains_key("xpath");
                let has_dsl = extractor_map.contains_key("dsl");

                if !has_regex && !has_kval && !has_json && !has_xpath && !has_dsl {
                    diagnostics.push(
                        TemplateDiagnostic::warning(
                            "yaml.extractor_missing_type",
                            format!(
                                "{}.extractors[{}]: Extractor should have 'type' field. Valid: {}",
                                context, idx, VALID_EXTRACTOR_TYPES.join(", ")
                            ),
                        )
                    );
                }
            }

            // Check for name field (used for variable extraction)
            if !extractor_map.contains_key("name") && !extractor_map.contains_key("internal") {
                diagnostics.push(
                    TemplateDiagnostic::info(
                        "yaml.extractor_no_name",
                        format!(
                            "{}.extractors[{}]: Consider adding 'name' field to use extracted value as variable",
                            context, idx
                        ),
                    )
                );
            }
        } else {
            diagnostics.push(
                TemplateDiagnostic::error(
                    "yaml.extractor_not_mapping",
                    format!("{}.extractors[{}]: Each extractor must be a mapping", context, idx),
                )
            );
        }
    }
    
    diagnostics
}

/// Look for matchers in the entire document
fn validate_matchers_in_document(yaml_map: &serde_yaml::Mapping, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    // Check top-level matchers
    if let Some(matchers) = yaml_map.get("matchers") {
        diagnostics.extend(validate_matchers(matchers, code, "root"));
    }

    // Check matchers-condition at root
    if let Some(cond) = yaml_map.get("matchers-condition").and_then(|v| v.as_str()) {
        if !VALID_MATCHER_CONDITIONS.contains(&cond.to_lowercase().as_str()) {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "yaml.invalid_matchers_condition",
                    format!("Invalid matchers-condition '{}'. Valid: and, or", cond),
                )
            );
        }
    }
    
    diagnostics
}

/// Look for extractors in the entire document  
fn validate_extractors_in_document(yaml_map: &serde_yaml::Mapping, code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    // Check top-level extractors
    if let Some(extractors) = yaml_map.get("extractors") {
        diagnostics.extend(validate_extractors(extractors, code, "root"));
    }
    
    diagnostics
}

/// Validate variable references {{variable}}
fn validate_variable_references(code: &str) -> Vec<TemplateDiagnostic> {
    let mut diagnostics = Vec::new();
    
    // Find all {{variable}} references
    let var_re = regex::Regex::new(r"\{\{([^}]+)\}\}").unwrap();
    let mut found_vars: Vec<String> = Vec::new();
    
    for caps in var_re.captures_iter(code) {
        if let Some(var_match) = caps.get(1) {
            let var_name = var_match.as_str().trim();
            found_vars.push(var_name.to_string());
        }
    }

    // Common built-in variables
    let builtin_vars = vec![
        "BaseURL", "Hostname", "Host", "Port", "Path", "Scheme",
        "RootURL", "interactsh-url", "rand_int", "rand_char", "rand_base64",
        "rand_text_alpha", "rand_text_alphanumeric", "timestamp", "unix_timestamp",
    ];

    // Check for potentially undefined variables
    for var in &found_vars {
        // Skip built-in variables
        let var_lower = var.to_lowercase();
        let is_builtin = builtin_vars.iter().any(|b| b.to_lowercase() == var_lower);
        
        // Skip DSL expressions (contain operators or function calls)
        let is_dsl = var.contains('(') || var.contains('+') || var.contains('-') 
            || var.contains('*') || var.contains('/') || var.contains('=');

        if !is_builtin && !is_dsl {
            // Check if variable is defined as extractor name
            let is_extractor = code.contains(&format!("name: {}", var))
                || code.contains(&format!("name: \"{}\"", var))
                || code.contains(&format!("name: '{}'", var));

            if !is_extractor && !var.starts_with("rand_") && !var.starts_with("interactsh") {
                // Find line number
                let line = code.lines()
                    .enumerate()
                    .find(|(_, line)| line.contains(&format!("{{{{{}}}}}", var)))
                    .map(|(idx, _)| idx + 1);

                diagnostics.push(
                    TemplateDiagnostic::info(
                        "yaml.undefined_variable",
                        format!(
                            "Variable '{{{{{}}}}}' used but not found as extractor name. \
                             Ensure it's defined or is a built-in variable.",
                            var
                        ),
                    )
                    .with_location(line.unwrap_or(1), None)
                );
            }
        }
    }

    // Check for malformed variable syntax
    for (line_num, line) in code.lines().enumerate() {
        // Check for single braces that might be typos
        if (line.contains("{") && !line.contains("{{")) || (line.contains("}") && !line.contains("}}")) {
            // Skip YAML mappings and obvious non-variable cases
            if !line.trim().ends_with(":") && !line.contains(": {") && !line.contains("}: ") {
                // Skip if it looks like intentional single brace
                if line.contains("\\{") || line.contains("\\}") {
                    continue;
                }
            }
        }

        // Check for unclosed variable references
        let open_count = line.matches("{{").count();
        let close_count = line.matches("}}").count();
        if open_count != close_count {
            diagnostics.push(
                TemplateDiagnostic::warning(
                    "yaml.unclosed_variable",
                    format!(
                        "Line has unbalanced variable braces: {} opening '{{{{' vs {} closing '}}}}'",
                        open_count, close_count
                    ),
                )
                .with_location(line_num + 1, None)
            );
        }
    }
    
    diagnostics
}

/// Helper to find line number of a YAML field
fn find_yaml_field_line(code: &str, field: &str) -> Option<usize> {
    code.lines()
        .enumerate()
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with(&format!("{}:", field)) 
                || trimmed.starts_with(&format!("{} :", field))
                || trimmed == &format!("- {}:", field)
        })
        .map(|(idx, _)| idx + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_yaml_template() {
        let yaml = r#"
id: test-template
name: Test Template
author:
  name: test
severity: high
description: A test template
language: yaml

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    matchers:
      - type: word
        words:
          - "success"
"#;
        let diags = validate(yaml).unwrap();
        let errors: Vec<_> = diags.iter().filter(|d| d.severity == super::super::DiagnosticSeverity::Error).collect();
        assert!(errors.is_empty(), "Valid template should have no errors: {:?}", errors);
    }

    #[test]
    fn test_invalid_matcher_type() {
        let yaml = r#"
id: test
name: Test
author: test
severity: high
description: Test
language: yaml

http:
  - method: GET
    path:
      - "/"
    matchers:
      - type: invalid_type
        words:
          - "test"
"#;
        let diags = validate(yaml).unwrap();
        assert!(diags.iter().any(|d| d.code == "yaml.invalid_matcher_type"));
    }

    #[test]
    fn test_missing_required_fields() {
        let yaml = r#"
id: test
http:
  - path:
      - "/"
"#;
        let diags = validate(yaml).unwrap();
        assert!(diags.iter().any(|d| d.code.contains("missing_")));
    }

    #[test]
    fn test_invalid_port() {
        let yaml = r#"
id: test
name: Test
author: test
severity: high
description: Test
language: yaml

network:
  - port: 99999
    inputs:
      - data: "test"
"#;
        let diags = validate(yaml).unwrap();
        assert!(diags.iter().any(|d| d.code == "yaml.invalid_port"));
    }

    #[test]
    fn test_regex_compilation() {
        let yaml = r#"
id: test
name: Test
author: test
severity: high
description: Test
language: yaml

http:
  - path:
      - "/"
    matchers:
      - type: regex
        regex:
          - "[invalid(regex"
"#;
        let diags = validate(yaml).unwrap();
        assert!(diags.iter().any(|d| d.code == "yaml.invalid_regex_pattern"));
    }
}
