use cosmwasm_std::testing::MockStorage;
use cosmwasm_std::Empty;
use cw_multi_test::{App, FailingModule, Module};

/// Utility function for asserting outputs returned from failing module.
fn assert_results(failing_module: FailingModule<Empty, Empty, Empty>) {
    let app = App::default();
    let mut storage = MockStorage::default();
    assert_eq!(
        r#"Unexpected exec msg Empty from Addr("cosmwasm1pgm8hyk0pvphmlvfjc8wsvk4daluz5tgrw6pu5mfpemk74uxnx9qlm3aqg")"#,
        failing_module
            .execute(
                app.api(),
                &mut storage,
                app.router(),
                &app.block_info(),
                app.api().addr_make("sender"),
                Empty {}
            )
            .unwrap_err()
            .to_string()
    );
    assert_eq!(
        "Unexpected custom query Empty",
        failing_module
            .query(
                app.api(),
                &storage,
                &(*app.wrap()),
                &app.block_info(),
                Empty {}
            )
            .unwrap_err()
            .to_string()
    );
    assert_eq!(
        "Unexpected sudo msg Empty",
        failing_module
            .sudo(
                app.api(),
                &mut storage,
                app.router(),
                &app.block_info(),
                Empty {}
            )
            .unwrap_err()
            .to_string()
    );
}

#[test]
fn failing_module_default_works() {
    assert_results(FailingModule::default());
}

#[test]
fn failing_module_new_works() {
    assert_results(FailingModule::new());
}
