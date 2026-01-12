//! Package manifests for all supported languages

use serde::{Deserialize, Serialize};

/// Package manifest for a language
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Programming language name

    pub language: String,
    /// Essential packages required for basic functionality

    pub essential: Vec<String>,
    /// Security-related packages

    pub security: Vec<String>,
    /// Web-related packages

    pub web: Vec<String>,
    /// Network-related packages

    pub network: Vec<String>,
    /// Parsing and data processing packages

    pub parsing: Vec<String>,
    /// Database client packages

    pub databases: Vec<String>,
    /// Utility packages

    pub utilities: Vec<String>,
}

impl PackageManifest {
    /// Get all packages
    pub fn all_packages(&self) -> Vec<String> {
        let mut packages = Vec::new();
        packages.extend(self.essential.clone());
        packages.extend(self.security.clone());
        packages.extend(self.web.clone());
        packages.extend(self.network.clone());
        packages.extend(self.parsing.clone());
        packages.extend(self.databases.clone());
        packages.extend(self.utilities.clone());
        packages
    }
}

/// Python package manifest
pub fn python_manifest() -> PackageManifest {
    PackageManifest {
        language: "python".to_string(),
        essential: vec![
            "pip".to_string(),
            "setuptools".to_string(),
            "wheel".to_string(),
        ],
        security: vec![
            "requests".to_string(),
            "urllib3".to_string(),
            "cryptography".to_string(),
            "paramiko".to_string(),
            "pycryptodome".to_string(),
            "python-nmap".to_string(),
            "scapy".to_string(),
            "impacket".to_string(),
            "pwntools".to_string(),
            "pyopenssl".to_string(),
        ],
        web: vec![
            "beautifulsoup4".to_string(),
            "lxml".to_string(),
            "selenium".to_string(),
            "scrapy".to_string(),
            "httpx".to_string(),
            "aiohttp".to_string(),
            "flask".to_string(),
            "django".to_string(),
            "fastapi".to_string(),
        ],
        network: vec![
            // Note: socket and asyncio are built-in, not installable
            "websockets".to_string(),
            "twisted".to_string(),
            "pyzmq".to_string(),
        ],
        parsing: vec![
            "pyyaml".to_string(),
            "jinja2".to_string(),
            // lxml already in web section
            "xmltodict".to_string(),
            "jsonschema".to_string(),
            "toml".to_string(),
            // configparser is built-in
        ],
        databases: vec![
            "psycopg2-binary".to_string(),
            "pymysql".to_string(),
            "pymongo".to_string(),
            "redis".to_string(),
            "sqlalchemy".to_string(),
        ],
        utilities: vec![
            "python-dotenv".to_string(),
            "colorama".to_string(),
            "tqdm".to_string(),
            "click".to_string(),
            "rich".to_string(),
            "pytest".to_string(),
        ],
    }
}

/// JavaScript/Node.js package manifest
pub fn javascript_manifest() -> PackageManifest {
    PackageManifest {
        language: "javascript".to_string(),
        essential: vec![
            "npm".to_string(),
        ],
        security: vec![
            "axios".to_string(),
            "node-fetch".to_string(),
            "puppeteer".to_string(),
            "playwright".to_string(),
            "jose".to_string(),
            "jsonwebtoken".to_string(),
            "bcrypt".to_string(),
            "crypto-js".to_string(),
        ],
        web: vec![
            "cheerio".to_string(),
            "jsdom".to_string(),
            "express".to_string(),
            "koa".to_string(),
            "fastify".to_string(),
            "socket.io".to_string(),
            "ws".to_string(),
        ],
        network: vec![
            // Note: net, http, https, dns are built-in Node.js modules
        ],
        parsing: vec![
            "yaml".to_string(),
            "xml2js".to_string(),
            "csv-parse".to_string(),
            "ajv".to_string(),
            "marked".to_string(),
        ],
        databases: vec![
            "pg".to_string(),
            "mysql2".to_string(),
            "mongodb".to_string(),
            "redis".to_string(),
            "sequelize".to_string(),
        ],
        utilities: vec![
            "dotenv".to_string(),
            "chalk".to_string(),
            "commander".to_string(),
            "inquirer".to_string(),
            "ora".to_string(),
            "jest".to_string(),
            "mocha".to_string(),
        ],
    }
}

/// Ruby package manifest
pub fn ruby_manifest() -> PackageManifest {
    PackageManifest {
        language: "ruby".to_string(),
        essential: vec![
            "bundler".to_string(),
        ],
        security: vec![
            "rest-client".to_string(),
            "httparty".to_string(),
            "mechanize".to_string(),
            "net-ssh".to_string(),
            "bcrypt".to_string(),
        ],
        web: vec![
            "nokogiri".to_string(),
            "sinatra".to_string(),
            "rails".to_string(),
            "rack".to_string(),
        ],
        network: vec![
            // Note: socket, net-http are built-in Ruby modules
        ],
        parsing: vec![
            // Note: json, yaml, csv are built-in Ruby modules
            "ox".to_string(),
        ],
        databases: vec![
            "pg".to_string(),
            "mysql2".to_string(),
            "mongo".to_string(),
            "redis".to_string(),
            "activerecord".to_string(),
        ],
        utilities: vec![
            "colorize".to_string(),
            "thor".to_string(),
            "rspec".to_string(),
        ],
    }
}

/// Perl package manifest
pub fn perl_manifest() -> PackageManifest {
    PackageManifest {
        language: "perl".to_string(),
        essential: vec![
            "App::cpanminus".to_string(),
        ],
        security: vec![
            "LWP::UserAgent".to_string(),
            "HTTP::Request".to_string(),
            "Net::SSH2".to_string(),
            "Crypt::SSLeay".to_string(),
        ],
        web: vec![
            "HTML::Parser".to_string(),
            "Web::Scraper".to_string(),
            "Mojolicious".to_string(),
            "Dancer2".to_string(),
        ],
        network: vec![
            "IO::Socket::INET".to_string(),
            "Net::DNS".to_string(),
        ],
        parsing: vec![
            "JSON".to_string(),
            "YAML".to_string(),
            "XML::LibXML".to_string(),
            "Text::CSV".to_string(),
        ],
        databases: vec![
            "DBI".to_string(),
            "DBD::Pg".to_string(),
            "DBD::mysql".to_string(),
            "MongoDB".to_string(),
            "Redis".to_string(),
        ],
        utilities: vec![
            "Term::ANSIColor".to_string(),
            "Getopt::Long".to_string(),
            "Test::More".to_string(),
        ],
    }
}

/// PHP package manifest
pub fn php_manifest() -> PackageManifest {
    PackageManifest {
        language: "php".to_string(),
        essential: vec![
            "composer/composer".to_string(),
        ],
        security: vec![
            "guzzlehttp/guzzle".to_string(),
            "phpseclib/phpseclib".to_string(),
            "firebase/php-jwt".to_string(),
        ],
        web: vec![
            "symfony/http-client".to_string(),
            "symfony/dom-crawler".to_string(),
            "fabpot/goutte".to_string(),
            "symfony/symfony".to_string(),
            "laravel/framework".to_string(),
        ],
        network: vec![
            "react/socket".to_string(),
            "ratchet/ratchet".to_string(),
        ],
        parsing: vec![
            "symfony/yaml".to_string(),
            "symfony/serializer".to_string(),
            "league/csv".to_string(),
        ],
        databases: vec![
            "doctrine/dbal".to_string(),
            "illuminate/database".to_string(),
            "mongodb/mongodb".to_string(),
            "predis/predis".to_string(),
        ],
        utilities: vec![
            "symfony/console".to_string(),
            "symfony/dotenv".to_string(),
            "phpunit/phpunit".to_string(),
        ],
    }
}

/// Go package manifest
pub fn go_manifest() -> PackageManifest {
    PackageManifest {
        language: "go".to_string(),
        essential: vec![],
        security: vec![
            "golang.org/x/crypto".to_string(),
            "github.com/golang-jwt/jwt".to_string(),
        ],
        web: vec![
            "github.com/gin-gonic/gin".to_string(),
            "github.com/gorilla/mux".to_string(),
            "github.com/PuerkitoBio/goquery".to_string(),
        ],
        network: vec![
            "github.com/gorilla/websocket".to_string(),
        ],
        parsing: vec![
            "gopkg.in/yaml.v3".to_string(),
            "encoding/json".to_string(),
            "encoding/xml".to_string(),
        ],
        databases: vec![
            "github.com/lib/pq".to_string(),
            "github.com/go-sql-driver/mysql".to_string(),
            "go.mongodb.org/mongo-driver".to_string(),
            "github.com/go-redis/redis".to_string(),
        ],
        utilities: vec![
            "github.com/spf13/cobra".to_string(),
            "github.com/joho/godotenv".to_string(),
            "github.com/stretchr/testify".to_string(),
        ],
    }
}

/// Rust package manifest
pub fn rust_manifest() -> PackageManifest {
    PackageManifest {
        language: "rust".to_string(),
        essential: vec![],
        security: vec![
            "reqwest".to_string(),
            "openssl".to_string(),
            "jsonwebtoken".to_string(),
            "bcrypt".to_string(),
        ],
        web: vec![
            "actix-web".to_string(),
            "axum".to_string(),
            "rocket".to_string(),
            "scraper".to_string(),
            "select".to_string(),
        ],
        network: vec![
            "tokio".to_string(),
            "async-std".to_string(),
            "tokio-tungstenite".to_string(),
        ],
        parsing: vec![
            "serde".to_string(),
            "serde_json".to_string(),
            "serde_yaml".to_string(),
            "toml".to_string(),
            "quick-xml".to_string(),
            "csv".to_string(),
        ],
        databases: vec![
            "sqlx".to_string(),
            "diesel".to_string(),
            "mongodb".to_string(),
            "redis".to_string(),
        ],
        utilities: vec![
            "clap".to_string(),
            "dotenv".to_string(),
            "tracing".to_string(),
            "colored".to_string(),
        ],
    }
}

/// Java package manifest
pub fn java_manifest() -> PackageManifest {
    PackageManifest {
        language: "java".to_string(),
        essential: vec![],
        security: vec![
            "org.apache.httpcomponents:httpclient".to_string(),
            "io.jsonwebtoken:jjwt".to_string(),
            "org.bouncycastle:bcprov-jdk15on".to_string(),
        ],
        web: vec![
            "org.jsoup:jsoup".to_string(),
            "org.springframework.boot:spring-boot-starter-web".to_string(),
        ],
        network: vec![
            "io.netty:netty-all".to_string(),
        ],
        parsing: vec![
            "com.fasterxml.jackson.core:jackson-databind".to_string(),
            "org.yaml:snakeyaml".to_string(),
            "com.google.code.gson:gson".to_string(),
        ],
        databases: vec![
            "org.postgresql:postgresql".to_string(),
            "mysql:mysql-connector-java".to_string(),
            "org.mongodb:mongodb-driver-sync".to_string(),
            "redis.clients:jedis".to_string(),
        ],
        utilities: vec![
            "info.picocli:picocli".to_string(),
            "org.junit.jupiter:junit-jupiter".to_string(),
        ],
    }
}

/// Get manifest for a language
pub fn get_manifest(language: &str) -> Option<PackageManifest> {
    match language.to_lowercase().as_str() {
        "python" | "py" => Some(python_manifest()),
        "javascript" | "js" | "node" => Some(javascript_manifest()),
        "ruby" | "rb" => Some(ruby_manifest()),
        "perl" | "pl" => Some(perl_manifest()),
        "php" => Some(php_manifest()),
        "go" | "golang" => Some(go_manifest()),
        "rust" | "rs" => Some(rust_manifest()),
        "java" => Some(java_manifest()),
        _ => None,
    }
}
