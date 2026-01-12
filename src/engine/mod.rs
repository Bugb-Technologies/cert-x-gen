//! Template engine implementations

pub mod c;
pub mod common;
pub mod cpp;
pub mod go;
pub mod java;
pub mod javascript;
pub mod perl;
pub mod php;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod shell;
pub mod yaml;

// Re-exports
pub use c::CEngine;
pub use cpp::CppEngine;
pub use go::GoEngine;
pub use java::JavaEngine;
pub use javascript::JavaScriptEngine;
pub use perl::PerlEngine;
pub use php::PhpEngine;
pub use python::PythonEngine;
pub use ruby::RubyEngine;
pub use rust::RustEngine;
pub use shell::ShellEngine;
pub use yaml::YamlTemplateEngine;
