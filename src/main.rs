use dotenv_codegen::dotenv;
use proto::firewall_client::FirewallClient;
use proto::FirewallRequest;
use std::env::{current_dir, var};
use std::error::Error;
use std::process::exit;
use tonic::transport::Endpoint;
use tonic::Request;
use users::get_current_username;

const SERVER_ADDR: &'static str = dotenv!("SERVER_ADDR");
const ERROR_CODE: i32 = 1;

mod proto {
    tonic::include_proto!("secu_score");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set silent panic hook
    std::panic::set_hook(Box::new(|_| {
        exit(ERROR_CODE);
    }));

    // Get endpoint addr
    let Ok(addr) = SERVER_ADDR.parse::<Endpoint>() else {
        exit(ERROR_CODE);
    };

    // Create client
    let mut client = {
        let Ok(client) = FirewallClient::connect(addr).await else {
            exit(ERROR_CODE);
        };
        client
    };

    // Get CWD
    let Ok(path) = current_dir() else {
        exit(ERROR_CODE);
    };

    let Some(path) = path.to_str() else {
        exit(ERROR_CODE);
    };

    // Get username
    let Some(username) = get_current_username() else {
        exit(ERROR_CODE);
    };

    let Some(username) = username.to_str() else {
        exit(ERROR_CODE);
    };

    let Ok(command) = var("BASH_COMMAND") else {
        exit(ERROR_CODE);
    };

    // Request permission
    let request = Request::new(FirewallRequest {
        command,
        user: String::from(username),
        path: String::from(path),
    });

    // Get response
    let Ok(response) = client.check(request).await else {
        exit(ERROR_CODE);
    };
    let response = response.get_ref();

    // Check if command is permitted
    if !response.allowed {
        exit(1);
    }

    Ok(())
}
