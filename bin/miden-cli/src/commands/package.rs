use std::path::PathBuf;

use clap::{Parser, Subcommand};
use miden_client::assembly::MastNodeExt;
use miden_client::vm::{Package, PackageExport};

use crate::commands::call::load_package;
use crate::create_dynamic_table;
use crate::errors::CliError;

// PACKAGE COMMAND
// ================================================================================================

/// Inspect Miden packages (`.masp`).
#[derive(Debug, Clone, Parser)]
pub struct PackageCmd {
    #[command(subcommand)]
    action: PackageAction,
}

#[derive(Debug, Clone, Subcommand)]
enum PackageAction {
    /// Print a package's metadata, exports, and dependencies.
    ///
    /// The package is read from disk on its own, so this needs neither an initialized client nor a
    /// node connection.
    Inspect {
        /// Path to the `.masp` package file.
        #[arg(value_name = "FILE")]
        package: PathBuf,
        /// Also print the MASM disassembly of each exported procedure.
        #[arg(short, long)]
        verbose: bool,
    },
}

impl PackageCmd {
    pub fn execute(&self) -> Result<(), CliError> {
        match &self.action {
            PackageAction::Inspect { package, verbose } => {
                let package = load_package(package)?;
                inspect_package(&package, *verbose);
                Ok(())
            },
        }
    }
}

// PACKAGE INSPECTION
// ================================================================================================

/// Prints the package's metadata, followed by its exports and dependencies.
///
/// Exports are split by kind: procedures carry a signature and a MAST root, while constants and
/// types only carry a path, so listing them in a single table would leave most columns empty. With
/// `verbose`, the MASM disassembly of each exported procedure follows.
fn inspect_package(package: &Package, verbose: bool) {
    print_metadata(package);
    print_procedures(package);
    print_other_exports(package);
    print_dependencies(package);

    if verbose {
        print_disassembly(package);
    }
}

/// Prints the package's identity: name, version, digest, target type, and description.
fn print_metadata(package: &Package) {
    println!("Package:     {}", package.name);
    println!("Version:     {}", package.version);
    println!("Digest:      {}", package.digest().to_hex());
    println!("Kind:        {}", package.kind);
    if let Some(description) = &package.description {
        println!("Description: {description}");
    }
}

/// Prints a table of the procedures exported by the package.
///
/// Procedures are listed by their fully-qualified path rather than their bare name, since a package
/// may export the same leaf name from several modules.
fn print_procedures(package: &Package) {
    let procedures: Vec<_> =
        package.manifest.exports().filter_map(PackageExport::as_procedure).collect();

    if procedures.is_empty() {
        println!("\nProcedures: none");
        return;
    }

    println!("\nProcedures ({}):", procedures.len());
    let mut table = create_dynamic_table(&["Procedure", "Signature", "MAST Root"]);
    for procedure in procedures {
        table.add_row(vec![
            procedure.path.to_string(),
            procedure
                .signature
                .as_ref()
                .map_or_else(|| NO_SIGNATURE.to_string(), ToString::to_string),
            procedure.digest.to_hex(),
        ]);
    }
    println!("{table}");
}

/// Prints a table of the package's non-procedure exports, if it has any.
fn print_other_exports(package: &Package) {
    let others: Vec<(String, &str)> = package
        .manifest
        .exports()
        .filter_map(|export| match export {
            PackageExport::Procedure(_) => None,
            PackageExport::Constant(constant) => Some((constant.path.to_string(), "constant")),
            PackageExport::Type(ty) => Some((ty.path.to_string(), "type")),
        })
        .collect();

    if others.is_empty() {
        return;
    }

    println!("\nOther exports ({}):", others.len());
    let mut table = create_dynamic_table(&["Export", "Kind"]);
    for (path, kind) in others {
        table.add_row(vec![path, kind.to_string()]);
    }
    println!("{table}");
}

/// Prints a table of the packages this package depends on.
///
/// Each dependency is pinned by digest, which is what resolution actually matches on; the version
/// is shown alongside it because it is what a manifest declares.
fn print_dependencies(package: &Package) {
    let dependencies: Vec<_> = package.manifest.dependencies().collect();

    if dependencies.is_empty() {
        println!("\nDependencies: none");
        return;
    }

    println!("\nDependencies ({}):", dependencies.len());
    let mut table = create_dynamic_table(&["Dependency", "Version", "Kind", "Digest"]);
    for dependency in dependencies {
        table.add_row(vec![
            dependency.name.to_string(),
            dependency.version.to_string(),
            dependency.kind.to_string(),
            dependency.digest.to_hex(),
        ]);
    }
    println!("{table}");
}

/// Prints the MASM disassembly of every procedure exported by the package.
///
/// A procedure re-exported from a dependency resolves to an external node whose body lives in that
/// dependency's forest, so only its MAST root can be shown here.
fn print_disassembly(package: &Package) {
    let forest = package.mast_forest();

    for export in package.manifest.exports() {
        let Some(procedure) = export.as_procedure() else {
            continue;
        };

        println!("\nProcedure {} ({}):", procedure.path, procedure.digest.to_hex());

        match package
            .get_procedure_node_by_path(&*procedure.path)
            .and_then(|node_id| forest.get_node_by_id(node_id))
        {
            Some(node) => println!("{}", node.to_pretty_print(forest).to_pretty_string()),
            None => println!("{NO_BODY}"),
        }
    }
}

// CONSTANTS
// ================================================================================================

/// Placeholder shown for a procedure whose package does not record a type signature.
const NO_SIGNATURE: &str = "<unknown>";

/// Placeholder shown for a procedure whose body is not part of this package's MAST forest.
const NO_BODY: &str = "<not available in this package>";
