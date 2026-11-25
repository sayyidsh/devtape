#![deny(unsafe_op_in_unsafe_fn)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn decode_tape_json(data: &[u8]) -> PyResult<String> {
    dtp_wasm::decode_and_sanitize_tape_json(data)
        .map_err(|err| PyValueError::new_err(err.to_string()))
}

#[pyfunction]
fn sanitize_ansi(text: &str) -> String {
    dtp_codec::sanitize_ansi_for_replay(text)
}

#[pymodule]
fn devtape_dtp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decode_tape_json, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_ansi, m)?)?;
    Ok(())
}
