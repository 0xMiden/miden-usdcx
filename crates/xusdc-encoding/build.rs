//! Build-time assembly of the shipped xUSDC MASM.
//!
//! Assembles `asm/xreserve/` into a package, then every member of the `asm/components/` and
//! `asm/notes/` workspaces, and writes each one under `$OUT_DIR/assets/`. The MASM therefore enters
//! the binary at BUILD time: a syntax error, an unresolved import, or a warning fails `cargo build`
//! rather than surfacing only when the test gate runs, and nothing reads the source tree at runtime.
//!
//! It also extracts the MASM error constants into `$OUT_DIR/xreserve_errors.rs`, so the Rust names
//! for them are generated from the MASM that defines them instead of being maintained by hand.
//!
//! The `shared` module at the bottom is copied from the protocol crates' build scripts because the
//! pinned protocol rev predates `miden-protocol-build-utils`. Once the pin advances past that crate,
//! this file collapses onto `assemble_project` / `assemble_workspace` / `extract_all_masm_errors` /
//! `generate_error_file` and the copy is deleted.

use std::env;
use std::path::Path;
use std::sync::Arc;

use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt};
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{Assembler, ProjectTargetSelector};
use miden_core_lib::CoreLibrary;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_project::Workspace;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::ProtocolLib;
use miden_standards::StandardsLib;

// CONSTANTS
// ================================================================================================

const ASM_DIR: &str = "asm";
const ASM_XRESERVE_DIR: &str = "xreserve";
const ASM_COMPONENTS_DIR: &str = "components";
const ASM_NOTES_DIR: &str = "notes";
const ASSETS_DIR: &str = "assets";

/// Name of the manifest file defining a Miden project.
const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
///
/// `dev` keeps debug info in the assembled packages, so an execution failure can still be traced
/// back to a MASM source span.
const BUILD_PROFILE: &str = "dev";

const XRESERVE_ERRORS_RS_FILE: &str = "xreserve_errors.rs";
const XRESERVE_ERRORS_ARRAY_NAME: &str = "XRESERVE_ERRORS";

// PRE-PROCESSING
// ================================================================================================

fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");

    // Without this an assembly failure prints only the report's kind; with it, the source span.
    let _ = miden_assembly::diagnostics::reporting::set_hook(Box::new(|_| {
        Box::new(miden_assembly::diagnostics::reporting::ReportHandlerOpts::new().build())
    }));

    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set");
    let build_dir = env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");

    let source_dir = Path::new(&crate_dir).join(ASM_DIR);
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    let mut registry = build_registry()?;

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);

    // The library is assembled first and seeded into the registry: both workspaces below declare it
    // as a dependency.
    compile_xreserve_lib(&source_dir, &target_dir, assembler.clone(), &mut registry)?;

    for workspace_dir in [ASM_COMPONENTS_DIR, ASM_NOTES_DIR] {
        compile_workspace(
            &source_dir.join(workspace_dir),
            &target_dir.join(workspace_dir),
            &assembler,
            &mut registry,
            source_manager.clone(),
        )?;
    }

    generate_error_constants(&source_dir, &build_dir)?;

    Ok(())
}

// ASSEMBLER & REGISTRY
// ================================================================================================

/// Builds the package registry that the declared dependencies resolve against.
///
/// The protocol package declares the kernel and core packages, and the xreserve projects declare the
/// standards package, so all four have to be present for dependency resolution to succeed.
fn build_registry() -> Result<InMemoryPackageRegistry> {
    let mut registry = InMemoryPackageRegistry::default();

    for package in [
        CoreLibrary::default().package(),
        ProtocolLib::default().package(),
        TransactionKernel::package(),
        StandardsLib::default().package(),
    ] {
        registry.cache_package(package).into_diagnostic()?;
    }

    Ok(registry)
}

// COMPILE PROJECTS
// ================================================================================================

/// Assembles the xreserve library project into a package, writes it to `target_dir`, and seeds it
/// into the `registry` so the component and note projects can resolve it.
fn compile_xreserve_lib(
    source_dir: &Path,
    target_dir: &Path,
    assembler: Assembler,
    registry: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_XRESERVE_DIR).join(PROJECT_MANIFEST);

    let package = assembler
        .for_project_at_path(manifest_path, registry)?
        .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

    package.write_masp_file(target_dir).into_diagnostic()?;

    registry.cache_package(package).into_diagnostic()?;

    Ok(())
}

/// Assembles every member of the workspace whose manifest sits in `source_dir` and writes each
/// package to `target_dir`. Each file is named after its package (e.g. `xreserve-faucet-extension.masp`), so
/// the package name is the include path the Rust side uses.
fn compile_workspace(
    source_dir: &Path,
    target_dir: &Path,
    assembler: &Assembler,
    registry: &mut InMemoryPackageRegistry,
    source_manager: Arc<dyn SourceManager>,
) -> Result<()> {
    let manifest = source_manager
        .load_file(&source_dir.join(PROJECT_MANIFEST))
        .into_diagnostic()?;
    let workspace = Workspace::load(manifest, source_manager.as_ref())?;

    for member in workspace.members() {
        let package = assembler
            .clone()
            .for_project(member.clone(), registry)?
            .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

        package.write_masp_file(target_dir).into_diagnostic()?;
    }

    Ok(())
}

// ERROR CONSTANTS FILE GENERATION
// ================================================================================================

/// Reads every MASM file under `asm_source_dir`, extracts its error constants and their messages,
/// and generates the Rust file that names them. For example
///
/// ```text
/// const ERR_XRESERVE_MINT_NOTE_INTENT_WORDS="mint note carries the wrong number of intent words"
/// ```
///
/// becomes
///
/// ```rust
/// pub const ERR_XRESERVE_MINT_NOTE_INTENT_WORDS: MasmError =
///     MasmError::from_static_str("mint note carries the wrong number of intent words");
/// ```
///
/// A constant defined twice is accepted only when both definitions carry the same message, which is
/// what lets a shared error live beside each procedure that raises it.
///
/// The generated file is written to `build_dir` (i.e. `OUT_DIR`) and pulled in with `include!`.
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    let errors = shared::extract_all_masm_errors(asm_source_dir)
        .context("failed to extract all masm errors")?;

    shared::generate_error_file(
        shared::ErrorModule {
            file_path: Path::new(build_dir).join(XRESERVE_ERRORS_RS_FILE),
            array_name: XRESERVE_ERRORS_ARRAY_NAME,
        },
        errors,
    )?;

    Ok(())
}

/// Copied from `miden-agglayer`'s build script at the pinned protocol rev. It is a stopgap: the
/// protocol has since extracted the same code into `miden-protocol-build-utils`, which replaces this
/// module wholesale once the pin advances past it.
mod shared {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    use std::io;
    use std::path::{Path, PathBuf};

    use fs_err as fs;
    use miden_assembly::diagnostics::{IntoDiagnostic, Result};
    use miden_assembly::Report;
    use regex::Regex;
    use walkdir::WalkDir;

    /// Returns true if the provided path resolves to a file with `.masm` extension.
    ///
    /// # Errors
    /// Returns an error if the path could not be converted to a UTF-8 string.
    pub fn is_masm_file(path: &Path) -> io::Result<bool> {
        if let Some(extension) = path.extension() {
            let extension = extension
                .to_str()
                .ok_or_else(|| io::Error::other("invalid UTF-8 filename"))?
                .to_lowercase();
            Ok(extension == "masm")
        } else {
            Ok(false)
        }
    }

    /// Extracts every masm error under the given path.
    pub fn extract_all_masm_errors(asm_source_dir: &Path) -> Result<Vec<NamedError>> {
        // A BTree orders the errors by category — the first part after the ERR_ prefix — and lets
        // the same error be defined in more than one file, as long as name and message both match.
        let mut errors = BTreeMap::new();

        for entry in WalkDir::new(asm_source_dir) {
            let entry = entry.into_diagnostic()?;
            if !is_masm_file(entry.path()).into_diagnostic()? {
                continue;
            }
            let file_contents = fs::read_to_string(entry.path()).into_diagnostic()?;
            extract_masm_errors(&mut errors, &file_contents)?;
        }

        let errors = errors
            .into_iter()
            .map(|(error_name, error)| NamedError {
                name: error_name,
                message: error.message,
            })
            .collect();

        Ok(errors)
    }

    /// Extracts the errors from a single masm file and inserts them into the provided map.
    pub fn extract_masm_errors(
        errors: &mut BTreeMap<ErrorName, ExtractedError>,
        file_contents: &str,
    ) -> Result<()> {
        let regex = Regex::new(r#"const\s*ERR_(?<name>.*)\s*=\s*"(?<message>.*)""#).unwrap();

        for capture in regex.captures_iter(file_contents) {
            let error_name = capture
                .name("name")
                .expect("error name should be captured")
                .as_str()
                .trim()
                .to_owned();
            let error_message = capture
                .name("message")
                .expect("error message should be captured")
                .as_str()
                .trim()
                .to_owned();

            if let Some(ExtractedError {
                message: existing_error_message,
            }) = errors.get(&error_name)
            {
                if existing_error_message != &error_message {
                    return Err(Report::msg(format!(
                        "error constant ERR_{error_name} is already defined elsewhere but its error message is different"
                    )));
                }
            }

            // Enforce the "no trailing punctuation" rule from the Rust error guidelines on MASM
            // errors.
            if error_message.ends_with('.') {
                return Err(Report::msg(format!(
                    "error messages should not end with a period: `ERR_{error_name}: {error_message}`"
                )));
            }

            errors.insert(
                error_name,
                ExtractedError {
                    message: error_message,
                },
            );
        }

        Ok(())
    }

    /// Returns true when `current_error` opens a category that `last_error` did not belong to.
    pub fn is_new_error_category<'a>(
        last_error: &mut Option<&'a str>,
        current_error: &'a str,
    ) -> bool {
        let is_new = match last_error {
            Some(last_err) => {
                let last_category = last_err
                    .split('_')
                    .next()
                    .expect("there should be at least one entry");
                let new_category = current_error
                    .split('_')
                    .next()
                    .expect("there should be at least one entry");
                last_category != new_category
            }
            None => false,
        };

        last_error.replace(current_error);

        is_new
    }

    /// Generates the content of the error file for the given set of errors and writes it to the path
    /// specified in the module.
    pub fn generate_error_file(module: ErrorModule, errors: Vec<NamedError>) -> Result<()> {
        let mut output = String::new();

        writeln!(output, "use miden_protocol::errors::MasmError;\n").unwrap();

        writeln!(
            output,
            "// This file is generated by build.rs, do not modify manually.
// It is generated by extracting errors from the MASM files in the `./asm` directory.
//
// To add a new error, define a constant in MASM of the pattern `const ERR_<CATEGORY>_...`.
// Try to fit the error into a pre-existing category if possible.
"
        )
        .unwrap();

        writeln!(
            output,
            "// {}
// ================================================================================================
",
            module.array_name.replace('_', " ")
        )
        .unwrap();

        let mut last_error = None;
        for named_error in errors.iter() {
            let NamedError { name, message } = named_error;

            // Group errors into blocks separated by newlines.
            if is_new_error_category(&mut last_error, name) {
                writeln!(output).into_diagnostic()?;
            }

            writeln!(output, "/// Error Message: \"{message}\"").into_diagnostic()?;
            writeln!(
                output,
                r#"pub const ERR_{name}: MasmError = MasmError::from_static_str("{message}");"#
            )
            .into_diagnostic()?;
        }

        write_if_changed(module.file_path, output.as_bytes())
    }

    /// Writes `contents` to `path` only if the file does not exist or its current contents differ.
    /// This avoids updating the file's mtime when nothing changed, which would otherwise make cargo
    /// treat the crate as dirty on the next build.
    pub fn write_if_changed(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
        let path = path.as_ref();
        let new_contents = contents.as_ref();
        if path.exists() {
            let existing = fs::read(path).into_diagnostic()?;
            if existing == new_contents {
                return Ok(());
            }
        }
        fs::write(path, new_contents).into_diagnostic()
    }

    pub type ErrorName = String;

    #[derive(Debug, Clone)]
    pub struct ExtractedError {
        pub message: String,
    }

    #[derive(Debug, Clone)]
    pub struct NamedError {
        pub name: ErrorName,
        pub message: String,
    }

    #[derive(Debug, Clone)]
    pub struct ErrorModule {
        pub file_path: PathBuf,
        pub array_name: &'static str,
    }
}
