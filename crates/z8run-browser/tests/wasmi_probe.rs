#![cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
fn trivial_app() {
    let wat = r#"(module
      (memory (export "memory") 1)
      (func (export "z8_alloc") (param i32) (result i32) i32.const 1024)
      (func (export "z8_process") (param i32 i32) (result i32)
        (local $i i32)
        (block $done (loop $l
          local.get $i i32.const 1 i32.add local.tee $i
          i32.const 1000 i32.lt_u
          br_if $l))
        (i32.store (i32.const 2048) (i32.const 2))
        (i32.store8 (i32.const 2052) (i32.const 123))
        (i32.store8 (i32.const 2053) (i32.const 125))
        i32.const 2048))"#;
    let wasm = wat::parse_str(wat).unwrap();
    let out = z8run_browser::wasmi_call_bytes(&wasm, "{}");
    assert!(out.is_ok(), "loop app: {out:?}");
}

#[wasm_bindgen_test]
fn echo_app() {
    let wasm = include_bytes!("../../../apps/echo/echo.wasm");
    let out = z8run_browser::wasmi_call_bytes(wasm, "{}");
    assert!(out.is_ok(), "echo app: {out:?}");
}
