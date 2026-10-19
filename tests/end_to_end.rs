//! Drives the full stack (CTAPHID -> CTAP2/U2F -> store/presence) through an in-process
//! fake HID transport, acting as the client.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use virtual_fido::authenticator::DEFAULT_AAGUID;
use virtual_fido::ctap2::cbor::{bytes, get, get_text, int, map, text};
use virtual_fido::ctap2::pin_protocol::{parse_cose_key, PinProtocol};
use virtual_fido::ctaphid::{self, ReportSink, Server, BROADCAST_CID, REPORT_SIZE};
use virtual_fido::presence::{AutoPresence, CancelToken, Presence, PresenceProvider, PresenceRequest};
use virtual_fido::store::{FileStore, KdfParams, MemoryStore};
use virtual_fido::Authenticator;

struct ChannelSink(Mutex<Sender<[u8; REPORT_SIZE]>>);

impl ReportSink for ChannelSink {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        let _ = self.0.lock().unwrap().send(*report);
        Ok(())
    }
}

/// Captures packets the client sends so they can be fed to the server.
struct Collect(Mutex<Vec<[u8; REPORT_SIZE]>>);

impl ReportSink for Collect {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        self.0.lock().unwrap().push(*report);
        Ok(())
    }
}

struct Client {
    server: Server,
    rx: Receiver<[u8; REPORT_SIZE]>,
    cid: u32,
    keepalives: Vec<u8>,
}

impl Client {
    fn new(presence: Arc<dyn PresenceProvider>) -> Self {
        Self::with_auth(Authenticator::new(Box::new(MemoryStore::default()), presence, DEFAULT_AAGUID))
    }

    fn with_auth(auth: Authenticator) -> Self {
        let (tx, rx) = mpsc::channel();
        let server = Server::new(Arc::new(ChannelSink(Mutex::new(tx))), auth);
        let mut c = Client { server, rx, cid: BROADCAST_CID, keepalives: Vec::new() };
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let (cmd, resp) = c.transact(ctaphid::CMD_INIT, &nonce);
        assert_eq!(cmd, ctaphid::CMD_INIT);
        assert_eq!(&resp[..8], &nonce);
        c.cid = u32::from_be_bytes(resp[8..12].try_into().unwrap());
        assert_ne!(c.cid, BROADCAST_CID);
        c
    }

    fn send(&mut self, cmd: u8, data: &[u8]) {
        let collect = Collect(Mutex::new(Vec::new()));
        ctaphid::send_message(&collect, self.cid, cmd, data).unwrap();
        for pkt in collect.0.into_inner().unwrap() {
            self.server.handle_report(&pkt);
        }
    }

    /// Reads one complete message, recording and skipping keepalives.
    fn recv(&mut self) -> (u8, Vec<u8>) {
        loop {
            let pkt = self.rx.recv_timeout(Duration::from_secs(5)).expect("response");
            assert!(pkt[4] & 0x80 != 0, "expected init packet");
            if pkt[4] & 0x7F == ctaphid::CMD_KEEPALIVE {
                self.keepalives.push(pkt[7]);
                continue;
            }
            assert_eq!(u32::from_be_bytes(pkt[..4].try_into().unwrap()), self.cid);
            let cmd = pkt[4] & 0x7F;
            let len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
            let mut data = pkt[7..7 + len.min(57)].to_vec();
            let mut seq = 0;
            while data.len() < len {
                let pkt = self.rx.recv_timeout(Duration::from_secs(5)).expect("continuation");
                assert_eq!(pkt[4], seq);
                seq += 1;
                let n = (len - data.len()).min(59);
                data.extend_from_slice(&pkt[5..5 + n]);
            }
            return (cmd, data);
        }
    }

    fn transact(&mut self, cmd: u8, data: &[u8]) -> (u8, Vec<u8>) {
        self.send(cmd, data);
        self.recv()
    }

    /// Sends a CTAP2 command; returns (status, decoded response map).
    fn ctap2(&mut self, cmd: u8, params: Option<Value>) -> (u8, Vec<(Value, Value)>) {
        let mut req = vec![cmd];
        if let Some(p) = params {
            ciborium::ser::into_writer(&p, &mut req).unwrap();
        }
        let (hid_cmd, resp) = self.transact(ctaphid::CMD_CBOR, &req);
        assert_eq!(hid_cmd, ctaphid::CMD_CBOR);
        let body = if resp.len() > 1 {
            match ciborium::de::from_reader(&resp[1..]).unwrap() {
                Value::Map(m) => m,
                other => panic!("not a map: {other:?}"),
            }
        } else {
            Vec::new()
        };
        (resp[0], body)
    }

    fn u2f(&mut self, apdu: &[u8]) -> (Vec<u8>, u16) {
        let (cmd, mut resp) = self.transact(ctaphid::CMD_MSG, apdu);
        assert_eq!(cmd, ctaphid::CMD_MSG);
        let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
        resp.truncate(resp.len() - 2);
        (resp, sw)
    }
}

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

fn make_credential_params(rp: &str, user: &[u8], name: &str, rk: bool, exclude: &[&[u8]]) -> Value {
    let mut entries = vec![
        (int(1), bytes(&[0x11; 32])),
        (int(2), map(vec![(text("id"), text(rp)), (text("name"), text(rp))])),
        (int(3), map(vec![(text("id"), bytes(user)), (text("name"), text(name))])),
        (int(4), Value::Array(vec![map(vec![(text("alg"), int(-7)), (text("type"), text("public-key"))])])),
        (int(7), map(vec![(text("rk"), Value::Bool(rk))])),
    ];
    if !exclude.is_empty() {
        let list = exclude.iter().map(|id| map(vec![(text("id"), bytes(id)), (text("type"), text("public-key"))]));
        entries.push((int(5), Value::Array(list.collect())));
    }
    map(entries)
}

fn get_assertion_params(rp: &str, cdh: &[u8; 32], allow: &[&[u8]]) -> Value {
    let mut entries = vec![(int(1), text(rp)), (int(2), bytes(cdh))];
    if !allow.is_empty() {
        let list = allow.iter().map(|id| map(vec![(text("id"), bytes(id)), (text("type"), text("public-key"))]));
        entries.push((int(3), Value::Array(list.collect())));
    }
    map(entries)
}

/// Parsed attested credential from makeCredential authData.
struct NewCredential {
    id: Vec<u8>,
    key: VerifyingKey,
    flags: u8,
}

fn parse_make_credential(rp: &str, resp: &[(Value, Value)]) -> NewCredential {
    assert_eq!(get(resp, 1).unwrap().as_text(), Some("packed"));
    let ad = get(resp, 2).unwrap().as_bytes().unwrap();
    assert_eq!(&ad[..32], &sha256(rp.as_bytes()));
    assert_eq!(ad[32] & 0x41, 0x41, "UP | AT");
    assert_eq!(&ad[37..53], &DEFAULT_AAGUID);
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let id = ad[55..55 + id_len].to_vec();
    let cose: Value = ciborium::de::from_reader(&ad[55 + id_len..]).unwrap();
    let cose = cose.as_map().unwrap();
    let x = get(cose, -2).unwrap().as_bytes().unwrap();
    let y = get(cose, -3).unwrap().as_bytes().unwrap();
    let key = VerifyingKey::from_sec1_bytes(&[&[4u8][..], x, y].concat()).unwrap();

    // Self attestation verifies with the credential key.
    let att = get(resp, 3).unwrap().as_map().unwrap();
    let sig = Signature::from_der(get_text(att, "sig").unwrap().as_bytes().unwrap()).unwrap();
    key.verify(&[ad, &[0x11u8; 32][..]].concat(), &sig).unwrap();
    NewCredential { id, key, flags: ad[32] }
}

fn verify_assertion(cred_key: &VerifyingKey, resp: &[(Value, Value)], cdh: &[u8; 32]) -> u32 {
    let ad = get(resp, 2).unwrap().as_bytes().unwrap();
    let sig = Signature::from_der(get(resp, 3).unwrap().as_bytes().unwrap()).unwrap();
    cred_key.verify(&[ad, &cdh[..]].concat(), &sig).unwrap();
    u32::from_be_bytes(ad[33..37].try_into().unwrap())
}

#[test]
fn ping_round_trips_multi_packet_messages() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    assert_eq!(c.transact(ctaphid::CMD_PING, &data), (ctaphid::CMD_PING, data));
}

#[test]
fn unknown_channel_is_rejected() {
    let mut c = Client::new(Arc::new(AutoPresence));
    c.cid = 0x1234_5678;
    assert_eq!(c.transact(ctaphid::CMD_PING, b"x"), (ctaphid::CMD_ERROR, vec![ctaphid::ERR_INVALID_CHANNEL]));
}

#[test]
fn get_info_advertises_fido2_and_u2f() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (status, info) = c.ctap2(0x04, None);
    assert_eq!(status, 0);
    let versions: Vec<_> = get(&info, 1).unwrap().as_array().unwrap().iter().map(|v| v.as_text().unwrap()).collect();
    assert_eq!(versions, ["U2F_V2", "FIDO_2_0"]);
    assert_eq!(get(&info, 3).unwrap().as_bytes().unwrap(), &DEFAULT_AAGUID);
    let opts = get(&info, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(opts, "rk").unwrap().as_bool(), Some(true));
}

#[test]
fn register_and_authenticate_with_allow_list() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (status, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", false, &[])));
    assert_eq!(status, 0);
    let cred = parse_make_credential("example.com", &resp);

    let cdh = [0x22; 32];
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id])));
    assert_eq!(status, 0);
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 1);
    assert!(get(&resp, 4).is_none(), "no user for non-discoverable credentials");
    let (_, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id])));
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 2, "counter increments");

    // Wrong RP, and non-discoverable credentials are not found without an allow list.
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("evil.com", &cdh, &[&cred.id]))).0, 0x2E);
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[]))).0, 0x2E);
}

#[test]
fn resident_keys_with_get_next_assertion() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, r1) = c.ctap2(0x01, Some(make_credential_params("example.com", b"u1", "alice", true, &[])));
    let alice = parse_make_credential("example.com", &r1);
    std::thread::sleep(Duration::from_millis(2));
    let (_, r2) = c.ctap2(0x01, Some(make_credential_params("example.com", b"u2", "bob", true, &[])));
    let bob = parse_make_credential("example.com", &r2);

    let cdh = [0x33; 32];
    let (status, first) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(status, 0);
    assert_eq!(get(&first, 5).unwrap().as_integer().map(i128::from), Some(2));
    let user = get(&first, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "name").unwrap().as_text(), Some("bob"), "newest first");
    verify_assertion(&bob.key, &first, &cdh);

    let (status, second) = c.ctap2(0x08, None);
    assert_eq!(status, 0);
    let user = get(&second, 4).unwrap().as_map().unwrap();
    assert_eq!(get_text(user, "id").unwrap().as_bytes().unwrap(), b"u1");
    verify_assertion(&alice.key, &second, &cdh);
    assert_eq!(c.ctap2(0x08, None).0, 0x30, "no more assertions");

    // Re-registering the same user replaces the old resident key.
    c.ctap2(0x01, Some(make_credential_params("example.com", b"u1", "alice2", true, &[])));
    let (_, first) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(get(&first, 5).unwrap().as_integer().map(i128::from), Some(2));
}

#[test]
fn exclude_list_and_reset() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let (_, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
    let cred = parse_make_credential("example.com", &resp);
    let (status, _) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[&cred.id])));
    assert_eq!(status, 0x19);

    assert_eq!(c.ctap2(0x07, None).0, 0);
    let cdh = [0; 32];
    assert_eq!(c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[&cred.id]))).0, 0x2E);
}

#[test]
fn rejects_unsupported_algorithms_and_uv() {
    let mut c = Client::new(Arc::new(AutoPresence));
    let params = map(vec![
        (int(1), bytes(&[0; 32])),
        (int(2), map(vec![(text("id"), text("example.com"))])),
        (int(3), map(vec![(text("id"), bytes(b"u"))])),
        (int(4), Value::Array(vec![map(vec![(text("alg"), int(-8)), (text("type"), text("public-key"))])])),
    ]);
    assert_eq!(c.ctap2(0x01, Some(params)).0, 0x26);
    let params = map(vec![(int(1), text("example.com")), (int(2), bytes(&[0; 32])), (int(5), map(vec![(text("uv"), Value::Bool(true))]))]);
    assert_eq!(c.ctap2(0x02, Some(params)).0, 0x2B);
    assert_eq!(c.ctap2(0x42, None).0, 0x01);
}

struct Deny;
impl PresenceProvider for Deny {
    fn request(&self, _: &PresenceRequest, _: &CancelToken) -> Presence {
        Presence::Denied
    }
}

#[test]
fn custom_presence_plugin_can_deny() {
    let mut c = Client::new(Arc::new(Deny));
    let (status, _) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
    assert_eq!(status, 0x27);
}

/// Blocks until cancelled.
struct WaitForCancel;
impl PresenceProvider for WaitForCancel {
    fn request(&self, _: &PresenceRequest, cancel: &CancelToken) -> Presence {
        while !cancel.is_cancelled() {
            std::thread::sleep(Duration::from_millis(10));
        }
        Presence::Cancelled
    }
}

#[test]
fn keepalives_while_waiting_and_cancel() {
    let mut c = Client::new(Arc::new(WaitForCancel));
    let mut req = vec![0x01];
    ciborium::ser::into_writer(&make_credential_params("example.com", b"a", "a", false, &[]), &mut req).unwrap();
    c.send(ctaphid::CMD_CBOR, &req);
    std::thread::sleep(Duration::from_millis(350));

    // Another channel is told the device is busy.
    let busy_cid = c.cid;
    c.cid = BROADCAST_CID;
    let (_, init) = c.transact(ctaphid::CMD_INIT, &[9; 8]);
    c.cid = u32::from_be_bytes(init[8..12].try_into().unwrap());
    assert_eq!(c.transact(ctaphid::CMD_PING, b"x"), (ctaphid::CMD_ERROR, vec![ctaphid::ERR_CHANNEL_BUSY]));
    c.cid = busy_cid;

    c.send(ctaphid::CMD_CANCEL, &[]);
    let (cmd, resp) = c.recv();
    assert_eq!((cmd, resp), (ctaphid::CMD_CBOR, vec![0x2D]));
    assert!(c.keepalives.len() >= 2, "got {} keepalives", c.keepalives.len());
    assert!(c.keepalives.iter().all(|&s| s == 2), "status UPNEEDED");
}

#[test]
fn u2f_register_and_authenticate() {
    let mut c = Client::new(Arc::new(AutoPresence));
    assert_eq!(c.u2f(&[0, 3, 0, 0, 0]), (b"U2F_V2".to_vec(), 0x9000));

    let challenge = [0xAA; 32];
    let app = sha256(b"https://example.com");
    let mut apdu = vec![0, 1, 3, 0, 64];
    apdu.extend_from_slice(&challenge);
    apdu.extend_from_slice(&app);
    let (resp, sw) = c.u2f(&apdu);
    assert_eq!(sw, 0x9000);
    assert_eq!(resp[0], 0x05);
    let pubkey = &resp[1..66];
    let kh_len = resp[66] as usize;
    let kh = resp[67..67 + kh_len].to_vec();
    let cred_key = VerifyingKey::from_sec1_bytes(pubkey).unwrap();

    let authenticate = |mode: u8, kh: &[u8]| {
        let mut apdu = vec![0, 2, mode, 0, (65 + kh.len()) as u8];
        apdu.extend_from_slice(&challenge);
        apdu.extend_from_slice(&app);
        apdu.push(kh.len() as u8);
        apdu.extend_from_slice(kh);
        apdu
    };
    assert_eq!(c.u2f(&authenticate(0x07, &kh)).1, 0x6985, "check-only: known handle");
    assert_eq!(c.u2f(&authenticate(0x07, &[0; 16])).1, 0x6A80, "check-only: unknown handle");

    let (resp, sw) = c.u2f(&authenticate(0x03, &kh));
    assert_eq!(sw, 0x9000);
    assert_eq!(resp[0], 0x01);
    let counter = &resp[1..5];
    let sig = Signature::from_der(&resp[5..]).unwrap();
    cred_key.verify(&[&app[..], &[0x01], counter, &challenge].concat(), &sig).unwrap();

    // The same credential works over CTAP2 when the RP ID hashes to the app parameter.
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("https://example.com", &[0; 32], &[&kh])));
    assert_eq!(status, 0);
    verify_assertion(&cred_key, &resp, &[0; 32]);
}

#[test]
fn file_store_persists_and_checks_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.bin");
    let params = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };
    let cdh = [0x44; 32];

    let cred = {
        let store = FileStore::open_with_params(&path, "hunter2", params).unwrap();
        let mut c = Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID));
        let (_, resp) = c.ctap2(0x01, Some(make_credential_params("example.com", b"alice", "alice", true, &[])));
        parse_make_credential("example.com", &resp)
    };

    assert!(FileStore::open(&path, "wrong").is_err());

    let store = FileStore::open(&path, "hunter2").unwrap();
    let mut c = Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID));
    let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
    assert_eq!(status, 0);
    assert_eq!(verify_assertion(&cred.key, &resp, &cdh), 1);

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

// ---- client PIN -------------------------------------------------------------------

impl Client {
    /// clientPIN request; `entries` excludes the protocol and subcommand.
    fn client_pin(&mut self, protocol: PinProtocol, sub: i64, mut entries: Vec<(Value, Value)>) -> (u8, Vec<(Value, Value)>) {
        entries.push((int(1), int(protocol.id())));
        entries.push((int(2), int(sub)));
        self.ctap2(0x06, Some(map(entries)))
    }

    /// Runs key agreement; returns our COSE key and the shared secret.
    fn key_agreement(&mut self, protocol: PinProtocol) -> (Value, Vec<u8>) {
        let (status, resp) = self.client_pin(protocol, 2, vec![]);
        assert_eq!(status, 0);
        let peer = parse_cose_key(get(&resp, 1).unwrap()).unwrap();
        let (cose, secret) = protocol.encapsulate(&peer);
        (cose, secret.to_vec())
    }

    fn set_pin(&mut self, protocol: PinProtocol, pin: &str) -> u8 {
        let (cose, secret) = self.key_agreement(protocol);
        let new_pin_enc = protocol.encrypt(&secret, &pad_pin(pin));
        let pin_auth = protocol.authenticate_with_secret(&secret, &new_pin_enc);
        self.client_pin(protocol, 3, vec![(int(3), cose), (int(4), bytes(&pin_auth)), (int(5), bytes(&new_pin_enc))]).0
    }

    fn change_pin(&mut self, protocol: PinProtocol, old: &str, new: &str) -> u8 {
        let (cose, secret) = self.key_agreement(protocol);
        let pin_hash_enc = protocol.encrypt(&secret, &sha256(old.as_bytes())[..16]);
        let new_pin_enc = protocol.encrypt(&secret, &pad_pin(new));
        let pin_auth = protocol.authenticate_with_secret(&secret, &[&new_pin_enc[..], &pin_hash_enc].concat());
        let entries = vec![(int(3), cose), (int(4), bytes(&pin_auth)), (int(5), bytes(&new_pin_enc)), (int(6), bytes(&pin_hash_enc))];
        self.client_pin(protocol, 4, entries).0
    }

    fn pin_token(&mut self, protocol: PinProtocol, pin: &str) -> Result<Vec<u8>, u8> {
        let (cose, secret) = self.key_agreement(protocol);
        let pin_hash_enc = protocol.encrypt(&secret, &sha256(pin.as_bytes())[..16]);
        let (status, resp) = self.client_pin(protocol, 5, vec![(int(3), cose), (int(6), bytes(&pin_hash_enc))]);
        if status != 0 {
            return Err(status);
        }
        let enc = get(&resp, 2).unwrap().as_bytes().unwrap();
        Ok(protocol.decrypt(&secret, enc).unwrap().to_vec())
    }

    fn pin_retries(&mut self) -> i128 {
        let (status, resp) = self.client_pin(PinProtocol::V1, 1, vec![]);
        assert_eq!(status, 0);
        get(&resp, 3).unwrap().as_integer().unwrap().into()
    }

    fn client_pin_option(&mut self) -> bool {
        let (_, info) = self.ctap2(0x04, None);
        get_text(get(&info, 4).unwrap().as_map().unwrap(), "clientPin").unwrap().as_bool().unwrap()
    }
}

fn pad_pin(pin: &str) -> Vec<u8> {
    let mut p = pin.as_bytes().to_vec();
    p.resize(64, 0);
    p
}

fn with_pin_auth(params: Value, key: (i64, i64), protocol: PinProtocol, token: &[u8], cdh: &[u8]) -> Value {
    let Value::Map(mut entries) = params else { unreachable!() };
    entries.push((int(key.0), bytes(&protocol.authenticate(token, cdh))));
    entries.push((int(key.1), int(protocol.id())));
    map(entries)
}

#[test]
fn pin_set_use_and_change() {
    for protocol in PinProtocol::SUPPORTED {
        let mut c = Client::new(Arc::new(AutoPresence));
        assert!(!c.client_pin_option());
        let (_, info) = c.ctap2(0x04, None);
        let protocols: Vec<i128> = get(&info, 6).unwrap().as_array().unwrap().iter().map(|v| v.as_integer().unwrap().into()).collect();
        assert_eq!(protocols, [2, 1]);
        assert_eq!(c.pin_token(protocol, "1234"), Err(0x35), "no PIN yet");

        assert_eq!(c.set_pin(protocol, "123"), 0x37, "too short");
        assert_eq!(c.set_pin(protocol, "1234"), 0);
        assert!(c.client_pin_option());
        assert_eq!(c.set_pin(protocol, "5678"), 0x30, "already set");

        // makeCredential now requires the PIN.
        let params = make_credential_params("example.com", b"alice", "alice", true, &[]);
        assert_eq!(c.ctap2(0x01, Some(params.clone())).0, 0x36);
        let token = c.pin_token(protocol, "1234").unwrap();
        assert_eq!(token.len(), 32);
        let (status, resp) = c.ctap2(0x01, Some(with_pin_auth(params.clone(), (8, 9), protocol, &token, &[0x11; 32])));
        assert_eq!(status, 0);
        let cred = parse_make_credential("example.com", &resp);
        assert_eq!(cred.flags, 0x45, "UP | UV | AT");
        let (status, _) = c.ctap2(0x01, Some(with_pin_auth(params, (8, 9), protocol, &token, &[0x99; 32])));
        assert_eq!(status, 0x33, "pinUvAuthParam over the wrong hash");

        // getAssertion works with or without the PIN; UV reflects which.
        let cdh = [0x55; 32];
        let (status, resp) = c.ctap2(0x02, Some(get_assertion_params("example.com", &cdh, &[])));
        assert_eq!(status, 0);
        assert_eq!(get(&resp, 2).unwrap().as_bytes().unwrap()[32], 0x01);
        let (status, resp) = c.ctap2(0x02, Some(with_pin_auth(get_assertion_params("example.com", &cdh, &[]), (6, 7), protocol, &token, &cdh)));
        assert_eq!(status, 0);
        assert_eq!(get(&resp, 2).unwrap().as_bytes().unwrap()[32], 0x05);
        verify_assertion(&cred.key, &resp, &cdh);

        assert_eq!(c.change_pin(protocol, "0000", "abcd"), 0x31, "wrong old PIN");
        assert_eq!(c.pin_retries(), 7);
        assert_eq!(c.change_pin(protocol, "1234", "abcd"), 0);
        assert_eq!(c.pin_retries(), 8);
        assert_eq!(c.pin_token(protocol, "1234"), Err(0x31));
        let new_token = c.pin_token(protocol, "abcd").unwrap();
        // Changing the PIN and issuing a new token invalidate the old one.
        let params = get_assertion_params("example.com", &cdh, &[]);
        assert_eq!(c.ctap2(0x02, Some(with_pin_auth(params.clone(), (6, 7), protocol, &token, &cdh))).0, 0x33);
        assert_eq!(c.ctap2(0x02, Some(with_pin_auth(params, (6, 7), protocol, &new_token, &cdh))).0, 0);
    }
}

#[test]
fn pin_retry_limits() {
    let p = PinProtocol::V2;
    let mut c = Client::new(Arc::new(AutoPresence));
    assert_eq!(c.set_pin(p, "1234"), 0);
    assert_eq!(c.pin_token(p, "0000"), Err(0x31));
    assert_eq!(c.pin_token(p, "0000"), Err(0x31));
    assert_eq!(c.pin_token(p, "0000"), Err(0x34), "third consecutive failure needs a power cycle");
    assert_eq!(c.pin_token(p, "1234"), Err(0x34), "even the right PIN");
    assert_eq!(c.pin_retries(), 5);
}

#[test]
fn pin_blocks_after_eight_failures_and_reset_clears_it() {
    let p = PinProtocol::V1;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.bin");
    let params = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };
    let new_client = || {
        let store = FileStore::open_with_params(&path, "pw", params).unwrap();
        Client::with_auth(Authenticator::new(Box::new(store), Arc::new(AutoPresence), DEFAULT_AAGUID))
    };

    let mut c = new_client();
    assert_eq!(c.set_pin(p, "1234"), 0);
    drop(c);
    let mut statuses = Vec::new();
    // Each "power cycle" (fresh authenticator on the same store) allows 3 more guesses.
    for _ in 0..3 {
        let mut c = new_client();
        for _ in 0..3 {
            statuses.push(c.pin_token(p, "0000").unwrap_err());
        }
    }
    assert_eq!(statuses, [0x31, 0x31, 0x34, 0x31, 0x31, 0x34, 0x31, 0x32, 0x32]);

    let mut c = new_client();
    assert_eq!(c.pin_retries(), 0, "retries persist across restarts");
    assert_eq!(c.pin_token(p, "1234"), Err(0x32), "blocked");
    assert_eq!(c.ctap2(0x07, None).0, 0);
    assert!(!c.client_pin_option(), "reset removes the PIN");
    assert_eq!(c.set_pin(p, "4321"), 0);
    assert!(c.pin_token(p, "4321").is_ok());
}
