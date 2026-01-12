//! Template engine implementations

pub mod common;
pub mod yaml;
pub mod python;
pub mod javascript;
pub mod rust;
pub mod shell;
pub mod c;
pub mod cpp;
pub mod java;
pub mod go;
pub mod ruby;
pub mod perl;
pub mod php;

// Re-exports
pub use yaml::YamlTemplateEngine;
pub use python::PythonEngine;
pub use javascript::JavaScriptEngine;
pub use rust::RustEngine;
pub use shell::ShellEngine;
pub use c::CEngine;
pub use cpp::CppEngine;
pub use java::JavaEngine;
pub use go::GoEngine;
pub use ruby::RubyEngine;
pub use perl::PerlEngine;
pub use php::PhpEngine;