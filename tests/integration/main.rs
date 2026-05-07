mod chaincode;
mod lifecycle;

// A single test entry point guarantees lifecycle (deploy) runs before chaincode (use),
// independent of how the test harness sorts test names.
#[test]
fn test_integration() {
    dotenv::dotenv().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            lifecycle::run().await;
            chaincode::run().await;
        });
}
