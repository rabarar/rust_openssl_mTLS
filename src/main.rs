use anyhow::{Result};
use anyhow::anyhow;
use anyhow::Context;


use openssl::ssl::{Ssl, SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use openssl::ssl::SslAcceptorBuilder;
use openssl::pkcs12::{Pkcs12};
use openssl::string::OpensslString;
use openssl::x509::{X509StoreContextRef, X509Ref, X509VerifyResult};
use openssl::nid::Nid;
use std::pin::Pin;

use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const TRUST_DEVICES: &str = "TrustedDevices";

#[tokio::main]
async fn main() -> Result<()> {

    let addr = "0.0.0.0:8443";

    let ca = X509::from_pem(&std::fs::read("client-ca.pem")?)?;

    let use_pem = true;
    let mut builder:SslAcceptorBuilder;
    
    // Build TLS acceptor (server config)
    if use_pem {
        builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key_file("key.pem", SslFiletype::PEM)?;
        builder.set_certificate_chain_file("cert.pem")?;
        builder.set_ca_file("client-ca.pem")?;
        builder.add_client_ca(&ca)?;
    } else {
        builder = build_acceptor_from_pkcs12("server.p12", "changeit")?;
        builder.set_ca_file("client-ca.pem")?;
        builder.add_client_ca(&ca)?;
    }

    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    builder.set_verify_callback(
    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    |preverified: bool, x509_ctx: &mut X509StoreContextRef| verifier_cb(preverified, x509_ctx));

    let acceptor = builder.build();

    // Bind TCP listener
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor).await {
                eprintln!("{}: {e:?}", peer);
            }
        });
    }
}

async fn handle_conn(tcp: TcpStream, acceptor: SslAcceptor) -> Result<()> {
    // Create Ssl from the acceptor’s context
    let ssl = Ssl::new(acceptor.context())?;

    // Wrap the TCP stream
    let mut tls = SslStream::new(ssl, tcp)?;

    // Async server-side handshake
    Pin::new(&mut tls).accept().await?; // <- correct call

    // (Optional) read the HTTP request so clients don't see EOF immediately
    let mut buf = [0u8; 4096];
    let _n = Pin::new(&mut tls).read(&mut buf).await.unwrap_or(0);

    // Write a simple HTTP response
    let body = b"ok\n";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
        body.len()
    );
    Pin::new(&mut tls).write_all(resp.as_bytes()).await?;
    Pin::new(&mut tls).write_all(body).await?;
    Pin::new(&mut tls).shutdown().await.ok(); // best-effort

    Ok(())
}

use openssl::x509::{X509, X509NameRef};

fn x509_name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for e in name.entries() {
        let key = e.object().nid().short_name().unwrap_or("UNKNOWN");
        let val = e.data().as_utf8()
            .map(|s| s.to_string())                // owned String
            .unwrap_or_else(|_| hex::encode(e.data().as_slice()));
        parts.push(format!("{key}={val}"));
    }
    parts.join(", ")
}



/// Heuristic to skip a root CA (self-signed) if it appears in the P12.
/// This keeps the server from sending the root to clients.

/// Robust self-signed check that works on a reference.
fn is_self_signed(cert: &X509Ref) -> bool {
    // OpenSSL will report OK if `cert` is issued by itself.
    cert.issued(cert) == X509VerifyResult::OK
}

/// Build an SslAcceptor from a PKCS#12 bundle (server key + leaf + chain).
/// Uses `parse2`, whose fields are: pkey: Option<...>, cert: Option<...>, ca: Stack<X509>.
pub fn build_acceptor_from_pkcs12(p12_path: &str, password: &str) -> Result<SslAcceptorBuilder> {
    let der = std::fs::read(p12_path)
        .with_context(|| format!("reading {}", p12_path))?;
    let p12 = Pkcs12::from_der(&der)?;
    let mut parsed = p12.parse2(password)?; // pkey: Option<PKey<Private>>, cert: Option<X509>, ca: Stack<X509>

    let pkey = parsed.pkey.ok_or_else(|| anyhow!("PKCS#12 has no private key"))?;
    let cert = parsed.cert.ok_or_else(|| anyhow!("PKCS#12 has no end-entity certificate"))?;

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_private_key(&pkey)?;
    builder.set_certificate(&cert)?;

    // IMPORTANT: iterate the *elements* with `.iter()` so each item is `&X509Ref`.
    for cert_ref in parsed.ca.iter_mut() {

        if let Some(cr) = cert_ref.pop() {
            if is_self_signed(cr.as_ref()) {
                continue; // don't send a self-signed root to clients
            }
            // Clone the element to an owned X509; add_extra_chain_cert takes ownership.
            let owned: X509 = cr.to_owned();
            builder.add_extra_chain_cert(owned)?;
        }
    }

    Ok(builder)
}

pub fn verifier_always_true_cb(_preverified: bool, _x509_ctx: &mut X509StoreContextRef) -> bool {
    eprintln!("always verified true!");
    true
}

pub fn verifier_cb(preverified: bool, x509_ctx: &mut X509StoreContextRef) -> bool {
    // display the chain
    if let Some(chain) = x509_ctx.chain() {
        for (i, c) in chain.iter().enumerate() {
            eprintln!("chain[{i}] subject={}", x509_name_to_string(c.subject_name()));
        }
    }

    // You can inspect the "current" cert in the chain:
    if let Some(cert) = x509_ctx.current_cert() {
        if let Some(cn) = cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
        {
            eprintln!("Verifying peer cert CN={}", cn);
        }
    }

    // Keep OpenSSL's verdict unless you have a strong reason to override:
    if !preverified {
        eprintln!("FAILED: PREVERIFIED: Verifying peer");
        return false;
    }

    // Only ENFORCE our policy on the LEAF certificate (depth 0).
    if x509_ctx.error_depth() != 0 {
        // Log if you want visibility, but don't enforce OU here.
        if let Some(c) = x509_ctx.current_cert() {
            eprintln!("chain[{}] subject={}", x509_ctx.error_depth(), {
                // small helper to print CN
                let cn = c.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|e| e.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                format!("CN={}", cn)
            });
        }
        return true;
    }

    // depth == 0 (leaf) — ENFORCE OU policy
    let Some(leaf) = x509_ctx.current_cert() else {
        eprintln!("no current cert at depth 0");
        return false;
    };


    let has_ou = leaf.subject_name()
        .entries_by_nid(Nid::ORGANIZATIONALUNITNAME)
        .any(|e| matches!(e.data().as_utf8(), Ok(s) if <OpensslString as AsRef<str>>::as_ref(&s) == TRUST_DEVICES));

    if !has_ou {
        // Helpful: print the full subject so you can see what’s actually there
        eprintln!("reject leaf: missing OU={}; subject={:?}", TRUST_DEVICES, {
            leaf.subject_name().entries()
                .filter_map(|e| e.data().as_utf8().ok()
                    .map(|v| format!("{}={}", e.object().nid().short_name().unwrap_or("?"), v)))
                .collect::<Vec<_>>()
                .join(", ")
        });
    }

    has_ou
}
