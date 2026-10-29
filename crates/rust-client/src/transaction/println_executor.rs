//! Program executor that prints the messages of `miden::println!`.
//!
//! Account and script code compiled with the Miden compiler calls `miden::println!` to emit the
//! `readonly::miden_debug::println` event. The transaction host does not handle this event, so the
//! message is lost. [`PrintlnProgramExecutor`] wraps the host and logs the message before the host
//! sees the event.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_processor::advice::{AdviceError, AdviceInputs, AdviceMutation};
use miden_processor::event::{EventError, TraceError};
use miden_processor::{
    BaseHost,
    ExecutionError,
    ExecutionOptions,
    ExecutionOutput,
    FastProcessor,
    FutureMaybeSend,
    Host,
    LoadedMastForest,
    ProcessorState,
    Program,
    ProgramExecutor,
    StackInputs,
    Word,
};
use miden_protocol::assembly::debuginfo::Location;
use miden_protocol::assembly::{SourceFile, SourceSpan};
use miden_protocol::vm::{DebugSourceNodeId, EventId, EventName, PackageDebugInfo};
use tracing::info;

/// Name of the event that `miden::println!` emits.
const PRINTLN_EVENT: EventName = EventName::new("readonly::miden_debug::println");

/// Largest message, in bytes, that the host reads from VM memory.
const MAX_PRINTLN_BYTES: usize = 512 * 1024;

// PRINTLN PROGRAM EXECUTOR
// ================================================================================================

/// [`ProgramExecutor`] that runs the program on a [`FastProcessor`] and logs `miden::println!`
/// messages with the `miden::println` tracing target.
pub struct PrintlnProgramExecutor {
    processor: FastProcessor,
}

impl ProgramExecutor for PrintlnProgramExecutor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Result<Self, AdviceError> {
        let processor =
            <FastProcessor as ProgramExecutor>::new(stack_inputs, advice_inputs, options)?;
        Ok(Self { processor })
    }

    fn with_debug_info(mut self, package_debug_info: PackageDebugInfo) -> Self {
        self.processor = ProgramExecutor::with_debug_info(self.processor, package_debug_info);
        self
    }

    fn with_entrypoint_source_node(
        mut self,
        entrypoint_source_node: Option<DebugSourceNodeId>,
    ) -> Self {
        self.processor =
            ProgramExecutor::with_entrypoint_source_node(self.processor, entrypoint_source_node);
        self
    }

    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        async move {
            let mut host = PrintlnHost { inner: host };
            ProgramExecutor::execute(self.processor, program, &mut host).await
        }
    }
}

// PRINTLN HOST
// ================================================================================================

/// [`Host`] that logs `miden::println!` messages and forwards every call to the wrapped host.
struct PrintlnHost<'a, H> {
    inner: &'a mut H,
}

impl<H: BaseHost> BaseHost for PrintlnHost<'_, H> {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.inner.resolve_event(event_id)
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        self.inner.resolve_trace(trace_id)
    }
}

impl<H: Host> Host for PrintlnHost<'_, H> {
    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        self.inner.get_mast_forest(node_digest)
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        if EventId::from_felt(process.get_stack_item(0)) == PRINTLN_EVENT.to_event_id() {
            match read_println_message(process) {
                Some(message) => info!(target: "miden::println", "{message}"),
                None => info!(target: "miden::println", "<unreadable println message>"),
            }
        }
        self.inner.on_event(process)
    }

    fn on_trace(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        self.inner.on_trace(process)
    }
}

/// Reads the message of a println event.
///
/// The operand stack holds `[event_id, byte_address, byte_length]`. Each memory element stores four
/// little-endian bytes. Returns `None` if the length is too large, the bytes are not UTF-8, or the
/// address range overflows.
fn read_println_message(process: &ProcessorState<'_>) -> Option<String> {
    let byte_address = u32::try_from(process.get_stack_item(1).as_canonical_u64()).ok()?;
    let length = usize::try_from(process.get_stack_item(2).as_canonical_u64()).ok()?;
    if length > MAX_PRINTLN_BYTES {
        return None;
    }

    let first_element = byte_address / 4;
    let skip = usize::try_from(byte_address % 4).ok()?;
    let element_count = u32::try_from((skip + length).div_ceil(4)).ok()?;

    let mut bytes = Vec::with_capacity(element_count as usize * 4);
    for index in 0..element_count {
        // Memory that the program never wrote reads as zero.
        let element = process
            .get_mem_value(process.ctx(), first_element.checked_add(index)?)
            .map_or(0, |felt| u32::try_from(felt.as_canonical_u64()).unwrap_or_default());
        bytes.extend(element.to_le_bytes());
    }

    String::from_utf8(bytes[skip..skip + length].to_vec()).ok()
}
