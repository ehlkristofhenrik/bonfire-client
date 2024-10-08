use dotenv_codegen::dotenv;
use proto::firewall_client::FirewallClient;
use proto::FirewallRequest;
use std::env::{current_dir, args};
use std::error::Error;
use std::process::exit;
use tonic::transport::Endpoint;
use tonic::Request;
use users::get_current_username;

const SERVER_ADDR: &'static str = dotenv!("SERVER_ADDR");

#[repr(i32)]
enum ErrorCode {
    EndpointParsingError = 1,
    ClientConnectionFailed,
    CwdNotFound,
    UserNotFound,
    CommandNotSet,
    ResponseError,
    AccessDenied,
    Other
}

mod proto {
    tonic::include_proto!("secu_score");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set silent panic hook
    std::panic::set_hook(Box::new(|_| {
        exit(ErrorCode::Other as i32);
    }));

    // Get endpoint addr
    let Ok(addr) = SERVER_ADDR.parse::<Endpoint>() else {
        exit(ErrorCode::EndpointParsingError as i32);
    };

    // Create client
    let Ok(mut client)  = FirewallClient::connect(addr).await else {
        exit(ErrorCode::ClientConnectionFailed as i32);
    };

    // Get CWD
    let Ok(path) = current_dir() else {
        exit(ErrorCode::CwdNotFound as i32);
    };

    let Some(path) = path.to_str() else {
        exit(ErrorCode::CwdNotFound as i32);
    };

    // Get username
    let Some(username) = get_current_username() else {
        exit(ErrorCode::UserNotFound as i32);
    };

    let Some(username) = username.to_str() else {
        exit(ErrorCode::UserNotFound as i32);
    };

    // Get command
    let Some(command) = args().nth(1) else {
        exit(ErrorCode::CommandNotSet as i32);
    };

    // Request permission
    #[cfg(not(feature = "dummy"))]
    let request = Request::new(FirewallRequest {
        command,
        user: String::from(username),
        path: String::from(path)
    });

    #[cfg(feature = "dummy")]
    let request = Request::new(FirewallRequest {
        command,
        user: "ehlkristofhenrik".to_string(),
        path: "/home/ehlkristofhenrik/".to_string()
    });

    // Get response
    let Ok( response ) = client.check(request).await else {
        exit(ErrorCode::ResponseError as i32);
    };
    let response = response.get_ref();

    // Check if command is permitted
    if !response.allowed {
        exit(ErrorCode::AccessDenied as i32);
    }

    Ok(())
}
