//! `DashCoreNode::start` when a port the node was given is taken before dashd binds it, and when
//! dashd fails to start for another reason.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use dash_spv::test_utils::{DashCoreNode, TestChain};
use tempfile::TempDir;

/// How soon a failed start must panic: well inside `DashCoreNode::start`'s 30 s ready timeout.
const FAIL_FAST_BOUND: Duration = Duration::from_secs(15);

/// A node on its own copy of the 200-block chain. The node is declared first, so dropping it
/// signals dashd to stop before the datadir is removed.
struct MinimalNode {
    node: DashCoreNode,
    datadir: TempDir,
}

fn minimal_node() -> Option<MinimalNode> {
    if std::env::var("SKIP_DASHD_TESTS").is_ok() {
        eprintln!("Skipping dashd integration test (SKIP_DASHD_TESTS is set)");
        return None;
    }
    let datadir = TempDir::new().expect("failed to create temp dir");
    let node = DashCoreNode::on_chain_copy(TestChain::Minimal, datadir.path())
        .expect("DASHD_TEST_DATA/regtest-200 not found");
    Some(MinimalNode {
        node,
        datadir,
    })
}

/// Asserts that dashd itself accepts connections on its P2P port: a connection to that port shows
/// up in its `getpeerinfo` as an inbound peer bound to it.
async fn assert_listens_on_p2p_port(node: &DashCoreNode) {
    let bind = format!("127.0.0.1:{}", node.p2p_port());
    let stream = tokio::net::TcpStream::connect(&bind).await.expect("connect to the P2P port");
    let local = stream.local_addr().expect("local address").to_string();
    for _ in 0..40 {
        let peers = node.try_rpc_call("getpeerinfo", &[]).expect("getpeerinfo");
        let listed = peers.as_array().expect("peer array").iter().any(|peer| {
            peer["inbound"] == true
                && peer["addr"] == local.as_str()
                && peer["addrbind"] == bind.as_str()
        });
        if listed {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("dashd lists no inbound peer from {} on {}", local, bind);
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "dashd sets SO_REUSEADDR, which on Windows lets it bind over the held listener"
)]
async fn start_moves_to_fresh_ports_when_its_p2p_port_is_taken() {
    let Some(mut t) = minimal_node() else {
        return;
    };
    let taken = t.node.p2p_port();
    let _holder = std::net::TcpListener::bind(("127.0.0.1", taken)).expect("hold the P2P port");

    let addr = t.node.start().await;

    assert_ne!(addr.port(), taken);
    assert_eq!(addr.port(), t.node.p2p_port());
    assert_listens_on_p2p_port(&t.node).await;
}

#[tokio::test]
async fn start_moves_to_fresh_ports_when_its_rpc_port_is_taken() {
    let Some(mut t) = minimal_node() else {
        return;
    };
    let taken = t.node.rpc_port();
    let _holder = std::net::TcpListener::bind(("127.0.0.1", taken)).expect("hold the RPC port");

    t.node.start().await;

    assert_ne!(t.node.rpc_port(), taken);
    assert_eq!(t.node.get_block_count(), 200);
    assert_listens_on_p2p_port(&t.node).await;
}

#[tokio::test]
async fn start_fails_at_once_when_dashd_exits_for_another_reason() {
    let Some(mut t) = minimal_node() else {
        return;
    };
    // dashd refuses a dash.conf with a line that isn't a setting. The test chain ships no
    // dash.conf, so this creates one; it is closed before dashd starts.
    {
        let mut conf = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(t.datadir.path().join("dash.conf"))
            .expect("open dash.conf");
        writeln!(conf, "this line is not a setting").expect("write dash.conf");
    }
    let p2p_port = t.node.p2p_port();
    let started = Instant::now();

    let panic = tokio::spawn(async move {
        t.node.start().await;
    })
    .await
    .expect_err("start must fail")
    .into_panic();

    let message = panic.downcast_ref::<String>().expect("panic message");
    assert!(message.starts_with("dashd exited during startup"), "{}", message);
    assert!(message.contains(&format!("(launch 1, P2P port {},", p2p_port)), "{}", message);
    assert!(started.elapsed() < FAIL_FAST_BOUND, "took {:?}", started.elapsed());

    // The failed start retained its datadir. Check that, then remove the copy so a passing run
    // leaves nothing in the uploaded test logs.
    if let Ok(retain_dir) = std::env::var("DASHD_TEST_RETAIN_DIR") {
        let test_name = std::thread::current().name().unwrap_or("unknown").replace(':', "_");
        let test_dir = Path::new(&retain_dir).join(test_name);
        let retained = test_dir.join(format!("dashd-{}", p2p_port));
        assert!(retained.join("regtest").is_dir(), "nothing retained at {}", retained.display());
        fs::remove_dir_all(&retained).expect("failed to remove the retained datadir");
        let _ = fs::remove_dir(&test_dir);
    }
}
