//! Poll-based reactor. This is a single-threaded reactor using a `poll` loop.
use crossbeam_channel as chan;

use nakamoto_net::error::Error;
use nakamoto_net::event::Publisher;
use nakamoto_net::time::{LocalDuration, LocalTime};
use nakamoto_net::{Disconnect, Io, PeerId};
use nakamoto_net::{Link, Service};

use log::*;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::io;
use std::io::prelude::*;
use std::net;
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time;
use std::time::SystemTime;
use bip324::{Handshake, Network, PacketHandler, PacketType, PacketWriter, Role};
use nakamoto_p2p::{DisconnectReason, Event};
use crate::fallible;
use crate::socket::Socket;
use crate::time::TimeoutManager;

/// Maximum time to wait when reading from a socket.
const READ_TIMEOUT: time::Duration = time::Duration::from_secs(6);
/// Maximum time to wait when writing to a socket.
const WRITE_TIMEOUT: time::Duration = time::Duration::from_secs(6);
/// Maximum amount of time to wait for i/o.
const WAIT_TIMEOUT: LocalDuration = LocalDuration::from_mins(60);
/// Socket read buffer size.
const READ_BUFFER_SIZE: usize = 1024 * 192;
// Version content is always empty for the current version of the protocol.
const VERSION_CONTENT: [u8; 0] = [];
// Number of bytes for the garbage terminator.
const NUM_GARBAGE_TERMINATOR_BYTES: usize = 16;
// Number of bytes used to indicate size when decrypting a message
const DEFAULT_SIZE_BYTES_V2: usize = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
enum Source<Id: PeerId> {
    Peer(Id),
    Listener,
    Waker,
}

#[derive(Clone)]
pub struct Waker(Arc<popol::Waker>);

impl Waker {
    fn new<Id: PeerId>(sources: &mut popol::Sources<Source<Id>>) -> io::Result<Self> {
        let waker = Arc::new(popol::Waker::new(sources, Source::Waker)?);

        Ok(Self(waker))
    }
}

impl nakamoto_net::Waker for Waker {
    fn wake(&self) -> io::Result<()> {
        self.0.wake()
    }
}

#[derive(Default)]
pub struct Bip324Info {
    v2: bool,
    key_sent: Option<Vec<u8>>,
    key_received: Option<Vec<u8>>,
    packet_handler: Option<PacketHandler>,
    handshake: Option<Box<Handshake<'static>>>,
    terminator_sent: Option<Vec<u8>>,
    terminator_received: Option<Vec<u8>>,
    message_buffer: Vec<u8>,
    pending_bytes: usize,
}

/// A single-threaded non-blocking reactor.
pub struct Reactor<R: Write + Read, Id: PeerId = net::SocketAddr> {
    peers: HashMap<Id, Socket<R>>,
    connecting: HashSet<Id>,
    sources: popol::Sources<Source<Id>>,
    waker: Waker,
    timeouts: TimeoutManager<()>,
    shutdown: chan::Receiver<()>,
    listening: chan::Sender<net::SocketAddr>,
    bip324_info: HashMap<Id, Bip324Info>,
}

/// The `R` parameter represents the underlying stream type, eg. `net::TcpStream`.
impl<R: Write + Read + AsRawFd, Id: PeerId> Reactor<R, Id> {
    /// Register a peer with the reactor.
    fn register_peer(&mut self, addr: Id, stream: R, link: Link) {
        let socket_addr = addr.to_socket_addr();
        self.sources
            .register(Source::Peer(addr.clone()), &stream, popol::interest::ALL);
        self.peers
            .insert(addr.clone(), Socket::from(stream, socket_addr, link));
        self.bip324_info.insert(addr, Bip324Info::default());
    }

    /// Unregister a peer from the reactor.
    fn unregister_peer<S>(
        &mut self,
        addr: Id,
        reason: Disconnect<S::DisconnectReason>,
        service: &mut S,
    ) where
        S: Service<Id>,
    {
        self.connecting.remove(&addr);
        self.peers.remove(&addr);
        self.sources.unregister(&Source::Peer(addr.clone()));

        service.disconnected(&addr, reason);
    }
}

impl<Id: PeerId> nakamoto_net::Reactor<Id> for Reactor<net::TcpStream, Id> {
    type Waker = Waker;

    /// Construct a new reactor, given a channel to send events on.
    fn new(
        shutdown: chan::Receiver<()>,
        listening: chan::Sender<net::SocketAddr>,
    ) -> Result<Self, io::Error> {
        let peers = HashMap::new();
        let bip324_info = HashMap::new();

        let mut sources = popol::Sources::new();
        let waker = Waker::new(&mut sources)?;
        let timeouts = TimeoutManager::new(LocalDuration::from_secs(1));
        let connecting = HashSet::new();

        Ok(Self {
            peers,
            connecting,
            sources,
            waker,
            timeouts,
            shutdown,
            listening,
            bip324_info,
        })
    }

    /// Run the given service with the reactor.
    fn run<S, E>(
        &mut self,
        listen_addrs: &[net::SocketAddr],
        mut service: S,
        mut publisher: E,
        commands: chan::Receiver<S::Command>,
    ) -> Result<(), Error>
    where
        S: Service<Id>,
        S::DisconnectReason: Into<Disconnect<S::DisconnectReason>>,
        E: Publisher<S::Event>,
    {
        let listener = if listen_addrs.is_empty() {
            None
        } else {
            let listener = self::listen(listen_addrs)?;
            let local_addr = listener.local_addr()?;

            self.sources
                .register(Source::Listener, &listener, popol::interest::READ);
            self.listening.send(local_addr).ok();

            info!(target: "net", "Listening on {}", local_addr);

            Some(listener)
        };

        info!(target: "net", "Initializing service..");

        let local_time = SystemTime::now().into();
        service.initialize(local_time);


        let mut io_queue: VecDeque<Io<Vec<u8>, Event, DisconnectReason, Id>> = VecDeque::new();
        self.process(&mut service, &mut publisher, local_time, &mut io_queue);

        // I/O readiness events populated by `popol::Sources::wait_timeout`.
        let mut events = Vec::with_capacity(32);
        // Timeouts populated by `TimeoutManager::wake`.
        let mut timeouts = Vec::with_capacity(32);

        loop {
            let timeout = self
                .timeouts
                .next(SystemTime::now())
                .unwrap_or(WAIT_TIMEOUT)
                .into();

            trace!(
                "Polling {} source(s) and {} timeout(s), waking up in {:?}..",
                self.sources.len(),
                self.timeouts.len(),
                timeout
            );

            let result = self.sources.wait_timeout(&mut events, timeout); // Blocking.
            let local_time = SystemTime::now().into();

            service.tick(local_time);

            match result {
                Ok(n) => {
                    trace!("Woke up with {n} source(s) ready");

                    for ev in events.drain(..) {
                        match &ev.key {
                            Source::Peer(addr) => {
                                let socket_addr = addr.to_socket_addr();
                                if ev.is_error() || ev.is_hangup() {
                                    // Let the subsequent read fail.
                                    trace!("{}: Socket error triggered: {:?}", socket_addr, ev);
                                }
                                if ev.is_invalid() {
                                    // File descriptor was closed and is invalid.
                                    // Nb. This shouldn't happen. It means the source wasn't
                                    // properly unregistered, or there is a duplicate source.
                                    error!(target: "net", "{}: Socket is invalid, removing", socket_addr);

                                    self.sources.unregister(&ev.key);
                                    continue;
                                }
                                if ev.is_writable() {
                                    self.handle_writable(addr.clone(), &ev.key, &mut service)?;
                                }
                                if ev.is_readable() {
                                    self.handle_readable(addr.clone(), &mut service);
                                }
                            }
                            Source::Listener => loop {
                                if let Some(ref listener) = listener {
                                    let (conn, socket_addr) = match listener.accept() {
                                        Ok((conn, socket_addr)) => (conn, socket_addr),
                                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            break;
                                        }
                                        Err(e) => {
                                            error!(target: "net", "Accept error: {}", e.to_string());
                                            break;
                                        }
                                    };
                                    let addr = Id::from(socket_addr);
                                    trace!("{}: Accepting peer connection", socket_addr);

                                    conn.set_nonblocking(true)?;

                                    let local_addr = conn.local_addr()?;
                                    let link = Link::Inbound;

                                    self.register_peer(addr.clone(), conn, link);
                                    service.connected(addr.clone(), &local_addr, link);
                                }
                            },
                            Source::Waker => {
                                trace!("Woken up by waker ({} command(s))", commands.len());

                                // Exit reactor loop if a shutdown was received.
                                if let Ok(()) = self.shutdown.try_recv() {
                                    return Ok(());
                                }
                                popol::Waker::reset(ev.source).ok();

                                // Nb. This should not happen, but it has been reported
                                // a few times. So we try to log a warning message and
                                // see how often this occurs.
                                if commands.is_empty() {
                                    log::warn!(target: "poll", "waken up by waker received without commands");
                                }

                                for cmd in commands.try_iter() {
                                    service.command_received(cmd);
                                }
                            }
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    // Nb. The way this is currently used basically ignores which keys have
                    // timed out. So as long as *something* timed out, we wake the service.
                    self.timeouts.wake(local_time, &mut timeouts);

                    if !timeouts.is_empty() {
                        timeouts.clear();
                        service.timer_expired();
                    }
                }
                Err(err) => return Err(err.into()),
            }
            self.process(&mut service, &mut publisher, local_time, &mut io_queue);
        }
    }

    /// Return a new waker.
    ///
    /// Used to wake up the main event loop.
    fn waker(&self) -> Self::Waker {
        self.waker.clone()
    }
}

impl<Id: PeerId> Reactor<net::TcpStream, Id> {
    /// Process service state machine outputs.
    fn process<S, E>(
        &mut self,
        service: &mut S,
        publisher: &mut E,
        local_time: LocalTime,
        io_queue: &mut VecDeque<Io<Vec<u8>, Event, DisconnectReason, Id>>
    )
    where
        S: Service<Id>,
        E: Publisher<S::Event>,
        S::DisconnectReason: Into<Disconnect<S::DisconnectReason>>,
    {
        io_queue.retain(|io| match io {
            Io::Write(addr, bytes) => {
                if let Some(bip324_info) = &mut self.bip324_info.get_mut(&addr) {
                    if bip324_info.key_sent.is_some()
                        && bip324_info.key_received.is_some()
                        && bip324_info.terminator_received.is_some()
                        && bip324_info.terminator_received.is_some() {
                        // Tambien añadir que compruebe que hay handshake. De esta manera puedo eliminar el
                        // flush del handle readable
                        let socket = match self.peers.get_mut(&addr) {
                            Some(socket) => socket,
                            None => return false,
                        };

                        let source = match self.sources.get_mut(&Source::Peer(addr.clone())) {
                            Some(source) => source,
                            None => return false,
                        };

                        if let Some(packet_handler) = &mut bip324_info.packet_handler {
                            let packet = packet_handler.writer().encrypt_packet(bytes.clone().as_slice(), None, PacketType::Genuine).unwrap();
                            println!("Encrypted message {:?}", packet.len());
                            socket.push(&packet);
                        } else {
                            //println!("Unencrypted message {:?}", bytes);
                            socket.push(bytes);
                        }
                        source.set(popol::interest::WRITE);
                        return false;
                    }
                }

                true
            }
            _ => false,
        });

        // Note that there may be messages destined for a peer that has since been
        // disconnected.
        while let Some(out) = service.next() {
            match out {
                Io::Write(addr, bytes) => {
                    if let Some(socket) = self.peers.get_mut(&addr.clone()) {
                        if let Some(source) = self.sources.get_mut(&Source::Peer(addr.clone())) {
                            if let Some(bip324_info) = &mut self.bip324_info.get_mut(&addr) {
                                if bip324_info.key_sent.is_some()
                                    && bip324_info.key_received.is_some()
                                    && bip324_info.terminator_received.is_some()
                                    && bip324_info.terminator_received.is_some() { // And v2 == true && bip324_info.packet_handler.is_some()
                                    if let Some(packet_handler) = &mut bip324_info.packet_handler {
                                        let packet = packet_handler.writer().encrypt_packet(bytes.clone().as_slice(), None, PacketType::Genuine).unwrap();
                                        //println!("encrypt");
                                        //println!("Plain message {:?}", bytes.len());
                                        println!("Encrypted message {:?}", packet.len());
                                        socket.push(&packet);
                                    } else {
                                        //println!("Unencrypted message {:?}", bytes);
                                        socket.push(&bytes);
                                    }
                                    source.set(popol::interest::WRITE);
                                } else {
                                    io_queue.push_back(Io::Write(addr, bytes));
                                }
                            }

                        }
                    }
                }
                Io::Connect(addr) => {
                    let socket_addr = addr.to_socket_addr();
                    trace!("Connecting to {}...", socket_addr);

                    match self::dial(&socket_addr) {
                        Ok(stream) => {
                            trace!("{:#?}", stream);
                            self.register_peer(addr.clone(), stream.try_clone().unwrap(), Link::Outbound);
                            self.connecting.insert(addr.clone());
                            // println!("registering: {:?}", self.peers);

                            let mut ellswift_buffer = vec![0u8; 64];
                            match Handshake::new(Network::Regtest, Role::Initiator, None, &mut ellswift_buffer) {
                                Ok(handshake) => {
                                    //println!("Sending key to {:?}: {:?}", socket_addr,  ellswift_buffer);

                                    let bip324_info = self.bip324_info.get_mut(&addr.clone()).unwrap();
                                    bip324_info.key_sent = Some(ellswift_buffer.to_vec());
                                    bip324_info.handshake = Some(Box::from(handshake));

                                    let socket = self.peers.get_mut(&addr).unwrap();
                                    socket.push(&ellswift_buffer);
                                },
                                Err(e) => continue,
                            };

                            service.attempted(&addr);
                        }
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            // Ignore. We are already establishing a connection through
                            // this socket.
                        }
                        Err(err) => {
                            error!(target: "net", "{}: Dial error: {}", socket_addr, err.to_string());

                            service.disconnected(&addr, Disconnect::DialError(Arc::new(err)));
                        }
                    }
                }
                Io::Disconnect(addr, reason) => {
                    if let Some(peer) = self.peers.get(&addr) {
                        trace!("{}: Disconnecting: {}", addr.to_socket_addr(), reason);
                        // Shutdown the connection, ignoring any potential errors.
                        // If the socket was already disconnected, this will yield
                        // an error that is safe to ignore (`ENOTCONN`). The other
                        // possible errors relate to an invalid file descriptor.
                        peer.disconnect().ok();

                        self.unregister_peer(addr, reason.into(), service);
                    }
                }
                Io::SetTimer(timeout) => {
                    self.timeouts.register((), local_time + timeout);
                }
                Io::Event(event) => {
                    trace!("Event: {:?}", event);

                    publisher.publish(event);
                }
            }
        }
    }

    fn handle_readable<S>(&mut self, addr: Id, service: &mut S)
    where
        S: Service<Id>,
    {
        // Nb. If the socket was readable and writable at the same time, and it was disconnected
        // during an attempt to write, it will no longer be registered and hence available
        // for reads.
        if let Some(socket) = self.peers.get_mut(&addr) {
            let mut buffer = [0; READ_BUFFER_SIZE];

            let socket_addr = addr.to_socket_addr();
            trace!("{}: Socket is readable", socket_addr);

            // Nb. Since `poll`, which this reactor is based on, is *level-triggered*,
            // we will be notified again if there is still data to be read on the socket.
            // Hence, there is no use in putting this socket read in a loop, as the second
            // invocation would likely block.
            match socket.read(&mut buffer) {
                Ok(count) => {
                    if count > 0 {
                        //println!("Reading {:?}", buffer[..count].to_vec());
                        trace!("{}: Read {} bytes", socket_addr, count);
                        let bip324_info = self.bip324_info.get_mut(&addr).unwrap();
                        if bip324_info.key_received.is_none() { // Añadir si es v2 y si hay packet handler
                            //println!("Received key from {} {:?}", socket_addr, &buffer[..count]);
                            bip324_info.key_received = Some(buffer[..count].to_vec());

                            if bip324_info.key_sent.is_none() {
                                let mut ellswift_buffer = vec![0u8; 64];
                                match Handshake::new(Network::Regtest, Role::Responder, None, &mut ellswift_buffer) {
                                    Ok(handshake) => {
                                        //println!("Inbound: Sending back key to {:?}: {:?}", socket_addr,  ellswift_buffer);
                                        bip324_info.key_sent = Some(ellswift_buffer.to_vec());
                                        bip324_info.handshake = Some(Box::from(handshake));
                                        socket.push(&ellswift_buffer);
                                        socket.flush().expect("flushed");
                                    },
                                    Err(e) => {},
                                };
                            }
                            Self::create_and_send_terminator(bip324_info, socket);
                        } else if bip324_info.terminator_received.is_none() {
                            bip324_info.terminator_received = Some(buffer[..count].to_vec());
                            // println!("Received: {:?}", bip324_info.terminator_received);
                            if let Some(mut handshake) = bip324_info.handshake.take() {
                                let terminator_copy = bip324_info.terminator_received.clone().unwrap();
                                if let Ok(()) = handshake.authenticate_garbage_and_version(
                                    &terminator_copy
                                ) {
                                    //println!("creating packet handler for {}", socket_addr);
                                    bip324_info.packet_handler = Some(handshake.finalize().expect("finalized"));
                                }
                            }
                        } else {
                            if let Some(packet_handler) = &mut bip324_info.packet_handler {
                                println!("Decrypting {} {:?}", count, &buffer[..150]);
                                // ignorar decoy
                                let message = &buffer[..count];
                                let mut pending_bytes = bip324_info.pending_bytes;
                                let mut index = 0;
                                let mut current_buffer = vec![];
                                let mut result_buffer = vec![];
                                println!("Amount to decrypt: {} {}", count, message.len());
                                // emptying pending message

                                if pending_bytes > 0 {
                                    if pending_bytes <= count {
                                        println!("Pending bytes: {}", pending_bytes);
                                        bip324_info.message_buffer.extend(message[..pending_bytes].to_vec());
                                        let result_message = packet_handler.reader().decrypt_payload(bip324_info.message_buffer.clone()[..].try_into().unwrap(), None).unwrap();
                                        result_buffer.extend_from_slice(&result_message.contents());
                                        bip324_info.message_buffer = vec![];
                                        bip324_info.pending_bytes = 0;
                                        index = pending_bytes;
                                    } else {
                                        println!("Cannot finish message");
                                        bip324_info.message_buffer.extend(message.to_vec());
                                        pending_bytes = pending_bytes - count;
                                    }
                                }

                                while index < count {
                                    println!("{} index before length: {}", socket_addr, index);
                                    for i in index..index+DEFAULT_SIZE_BYTES_V2 {
                                        current_buffer.push(message[i]);
                                    }
                                    index += DEFAULT_SIZE_BYTES_V2;
                                    println!("{} buffer length before length: {}", socket_addr, current_buffer.len());
                                    println!("{} buffer length: {:?}", socket_addr, current_buffer);
                                    let length = packet_handler.reader().decypt_len(current_buffer[..].try_into().unwrap());
                                    println!("{} length: {}", socket_addr, length);
                                    current_buffer.clear();
                                    let mut finish = index + length;
                                    if finish > count {
                                        bip324_info.pending_bytes = finish - count;
                                        bip324_info.message_buffer.extend(message[index..].to_vec());
                                        println!("Writing pending bytes: {}", bip324_info.pending_bytes);
                                        break;
                                    } else {
                                        for i in index..finish {
                                            current_buffer.push(message[i]);
                                        }
                                        println!("{} buffer length before reading: {}", socket_addr, current_buffer.len());
                                        index += length;
                                        let result_message = packet_handler.reader().decrypt_payload(current_buffer[..].try_into().unwrap(), None).unwrap();
                                        result_buffer.extend(result_message.contents());
                                        println!("index final: {}", index);
                                    }
                                    current_buffer.clear();
                                    println!("{} index before read: {}", socket_addr, index);
                                }
                                service.message_received(&addr, Cow::Borrowed(&result_buffer));
                            } else {
                                service.message_received(&addr, Cow::Borrowed(&buffer[..count]));
                            }
                        }
                    } else {
                        trace!("{}: Read 0 bytes", socket_addr);
                        // If we get zero bytes read as a return value, it means the peer has
                        // performed an orderly shutdown.
                        socket.disconnect().ok();
                        self.unregister_peer(
                            addr,
                            Disconnect::ConnectionError(Arc::new(io::Error::from(
                                io::ErrorKind::ConnectionReset,
                            ))),
                            service,
                        );
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // This shouldn't normally happen, since this function is only called
                    // when there's data on the socket. We leave it here in case external
                    // conditions change.
                }
                Err(err) => {
                    trace!("{}: Read error: {}", socket_addr, err.to_string());

                    socket.disconnect().ok();
                    self.unregister_peer(addr, Disconnect::ConnectionError(Arc::new(err)), service);
                }
            }
        }
    }

    fn handle_writable<S: Service<Id>>(
        &mut self,
        addr: Id,
        source: &Source<Id>,
        service: &mut S,
    ) -> io::Result<()> {
        let socket_addr = addr.to_socket_addr();
        trace!("{}: Socket is writable", socket_addr);

        let source = self.sources.get_mut(source).unwrap();
        let socket = self.peers.get_mut(&addr).unwrap();

        // "A file descriptor for a socket that is connecting asynchronously shall indicate
        // that it is ready for writing, once a connection has been established."
        //
        // Since we perform a non-blocking connect, we're only really connected once the socket
        // is writable.
        if self.connecting.remove(&addr) {
            let local_addr = socket.local_address()?;

            service.connected(addr.clone(), &local_addr, socket.link);
        }
        match socket.flush() {
            // In this case, we've written all the data, we
            // are no longer interested in writing to this
            // socket.
            Ok(()) => {
                source.unset(popol::interest::WRITE);
            }
            // In this case, the write couldn't complete. Set
            // our interest to `WRITE` to be notified when the
            // socket is ready to write again.
            Err(err)
                if [io::ErrorKind::WouldBlock, io::ErrorKind::WriteZero].contains(&err.kind()) =>
            {
                source.set(popol::interest::WRITE);
            }
            Err(err) => {
                error!(target: "net", "{}: Write error: {}", socket_addr, err.to_string());

                socket.disconnect().ok();
                self.unregister_peer(addr, Disconnect::ConnectionError(Arc::new(err)), service);
            }
        }
        Ok(())
    }

    fn create_and_send_terminator(bip324_info: &mut Bip324Info, socket: &mut Socket<TcpStream>) {
        let num_version_packet_bytes = PacketWriter::required_packet_allocation(&VERSION_CONTENT);
        let mut terminator_and_version_buffer =
            vec![0u8; NUM_GARBAGE_TERMINATOR_BYTES + num_version_packet_bytes];
        if let Some(handshake) = &mut bip324_info.handshake {
            handshake.complete_materials(
                bip324_info.key_received.clone().unwrap().try_into().unwrap(),
                &mut terminator_and_version_buffer,
                None
            ).unwrap();
        }
        socket.push(&terminator_and_version_buffer);
        socket.flush().expect("flushed");
        bip324_info.terminator_sent = Some(terminator_and_version_buffer.to_vec());
        // println!("Sending terminator {:?}", terminator_and_version_buffer);
    }

}

/// Connect to a peer given a remote address.
fn dial(addr: &net::SocketAddr) -> Result<net::TcpStream, io::Error> {
    use socket2::{Domain, Socket, Type};
    fallible! { io::Error::from(io::ErrorKind::Other) };

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, None)?;

    sock.set_read_timeout(Some(READ_TIMEOUT))?;
    sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
    sock.set_nonblocking(true)?;

    match sock.connect(&(*addr).into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) if e.raw_os_error() == Some(libc::EALREADY) => {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(sock.into())
}

// Listen for connections on the given address.
fn listen<A: net::ToSocketAddrs>(addr: A) -> Result<net::TcpListener, Error> {
    let sock = net::TcpListener::bind(addr)?;

    sock.set_nonblocking(true)?;

    Ok(sock)
}
