package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"goshark/internal/capturefile"
)

const (
	maxLiveSessions          = 4
	maxLiveSessionBytes      = 64 << 20
	maxLiveSessionPackets    = 4096
	maxLiveCaptureSpoolBytes = int64(1 << 30)
)

type liveSession struct {
	mu              sync.RWMutex
	packets         map[uint64]capturefile.Packet
	order           []uint64
	bytes           int
	spoolMu         sync.Mutex
	spoolDir        string
	spoolRoot       *os.Root
	spoolFile       *os.File
	spoolLinkType   uint32
	spoolSize       int64
	spoolHeader     bool
	spoolTruncated  bool
	captureFinished bool
	spoolErr        error
	closed          bool
}

func (s *Server) createLiveSession() (string, error) {
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return "", errors.New("could not create live capture session id")
	}
	id := hex.EncodeToString(randomID[:])
	directory, err := os.MkdirTemp("", "goshark-live-")
	if err != nil {
		return "", errors.New("could not create a private live capture spool")
	}
	spoolRoot, err := os.OpenRoot(directory)
	if err != nil {
		return "", errors.Join(errors.New("could not open private live capture spool directory"), os.RemoveAll(directory))
	}
	spoolFile, err := spoolRoot.OpenFile("capture.pcap", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.Join(errors.New("could not create live capture spool file"), spoolRoot.Close(), os.RemoveAll(directory))
	}
	newSession := &liveSession{
		packets:   make(map[uint64]capturefile.Packet),
		spoolDir:  directory,
		spoolRoot: spoolRoot,
		spoolFile: spoolFile,
	}
	var evicted []*liveSession
	s.sessionMu.Lock()
	if s.sessions == nil {
		s.sessions = make(map[string]*liveSession)
	}
	for len(s.sessionOrder) >= maxLiveSessions {
		oldest := s.sessionOrder[0]
		s.sessionOrder = s.sessionOrder[1:]
		if old := s.sessions[oldest]; old != nil {
			evicted = append(evicted, old)
			delete(s.sessions, oldest)
		}
	}
	s.sessions[id] = newSession
	s.sessionOrder = append(s.sessionOrder, id)
	s.sessionMu.Unlock()
	for _, old := range evicted {
		if err := old.close(); err != nil {
			return id, err
		}
	}
	return id, nil
}

func (s *Server) storeLivePacket(sessionID string, number uint64, packet capturefile.Packet) error {
	s.sessionMu.RLock()
	session := s.sessions[sessionID]
	s.sessionMu.RUnlock()
	if session == nil {
		return errors.New("live capture session is no longer available")
	}
	if err := session.writeSpool(packet); err != nil {
		return err
	}
	copyOfPacket := packet
	copyOfPacket.Data = append([]byte(nil), packet.Data...)
	session.mu.Lock()
	if existing, ok := session.packets[number]; ok {
		session.bytes -= len(existing.Data)
	} else {
		session.order = append(session.order, number)
	}
	session.packets[number] = copyOfPacket
	session.bytes += len(copyOfPacket.Data)
	for len(session.order) > maxLiveSessionPackets || session.bytes > maxLiveSessionBytes {
		oldest := session.order[0]
		session.order = session.order[1:]
		if existing, ok := session.packets[oldest]; ok {
			session.bytes -= len(existing.Data)
			delete(session.packets, oldest)
		}
	}
	session.mu.Unlock()
	return nil
}

func (session *liveSession) writeSpool(packet capturefile.Packet) error {
	session.spoolMu.Lock()
	defer session.spoolMu.Unlock()
	if session.closed || session.captureFinished {
		return errors.New("live capture spool is closed")
	}
	if session.spoolErr != nil {
		return session.spoolErr
	}
	if !session.spoolHeader {
		if err := capturefile.WritePCAPHeader(session.spoolFile, capturefile.DefaultLimits().MaxPacketBytes, packet.LinkType); err != nil {
			session.spoolErr = err
			return err
		}
		session.spoolSize = 24
		session.spoolLinkType = uint32(packet.LinkType)
		session.spoolHeader = true
	} else if session.spoolLinkType != uint32(packet.LinkType) {
		return errors.New("live capture changed link type during a session")
	}
	recordBytes := int64(16 + len(packet.Data))
	if recordBytes < 16 || session.spoolSize > maxLiveCaptureSpoolBytes-recordBytes {
		session.spoolTruncated = true
		return nil
	}
	if err := capturefile.WritePCAPPacket(session.spoolFile, packet, capturefile.DefaultLimits().MaxPacketBytes); err != nil {
		session.spoolErr = err
		return err
	}
	session.spoolSize += recordBytes
	return nil
}

func (s *Server) finishLiveSession(sessionID string) error {
	s.sessionMu.RLock()
	session := s.sessions[sessionID]
	s.sessionMu.RUnlock()
	if session == nil {
		return nil
	}
	session.spoolMu.Lock()
	defer session.spoolMu.Unlock()
	if session.captureFinished {
		return session.spoolErr
	}
	session.captureFinished = true
	if session.spoolFile != nil {
		if err := session.spoolFile.Sync(); err != nil {
			session.spoolErr = errors.Join(session.spoolErr, err)
		}
		if err := session.spoolFile.Close(); err != nil {
			session.spoolErr = errors.Join(session.spoolErr, err)
		}
		session.spoolFile = nil
	}
	return session.spoolErr
}

func (s *Server) livePacket(sessionID string, number uint64) (capturefile.Packet, error) {
	s.sessionMu.RLock()
	session := s.sessions[sessionID]
	s.sessionMu.RUnlock()
	if session == nil {
		return capturefile.Packet{}, errors.New("live capture session is no longer available")
	}
	session.mu.RLock()
	packet, ok := session.packets[number]
	if ok {
		packet.Data = append([]byte(nil), packet.Data...)
	}
	session.mu.RUnlock()
	if !ok {
		return capturefile.Packet{}, errors.New("packet has expired from the live capture detail buffer")
	}
	dataLength, err := intToUint32(len(packet.Data))
	if len(packet.Data) < 1 || err != nil || packet.Original < dataLength {
		return capturefile.Packet{}, errors.New("live capture detail buffer contains an invalid packet")
	}
	return packet, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func (s *Server) snapshotLiveCapture(ctx context.Context, sessionID string) (string, func(), bool, error) {
	s.sessionMu.RLock()
	session := s.sessions[sessionID]
	s.sessionMu.RUnlock()
	if session == nil {
		return "", nil, false, errors.New("live capture session is no longer available")
	}
	session.spoolMu.Lock()
	defer session.spoolMu.Unlock()
	if session.closed || session.spoolRoot == nil {
		return "", nil, false, errors.New("live capture spool is no longer available")
	}
	if !session.captureFinished {
		return "", nil, false, errors.New("stop the live capture before exporting its full recording")
	}
	if session.spoolErr != nil {
		return "", nil, session.spoolTruncated, session.spoolErr
	}
	if !session.spoolHeader || session.spoolSize <= 24 {
		return "", nil, session.spoolTruncated, errors.New("no packets were recorded in the live capture")
	}
	snapshot, err := os.CreateTemp("", "goshark-live-snapshot-*.pcap")
	if err != nil {
		return "", nil, session.spoolTruncated, errors.New("could not create a temporary live capture snapshot")
	}
	cleanup := func() { _ = os.Remove(snapshot.Name()) }
	source, err := session.spoolRoot.Open("capture.pcap")
	if err != nil {
		snapshotCloseErr := snapshot.Close()
		cleanup()
		return "", nil, session.spoolTruncated, errors.Join(err, snapshotCloseErr)
	}
	copied, copyErr := io.CopyN(snapshot, contextReader{ctx: ctx, reader: source}, session.spoolSize)
	closeSourceErr := source.Close()
	closeSnapshotErr := snapshot.Close()
	if copyErr != nil || closeSourceErr != nil || closeSnapshotErr != nil || copied != session.spoolSize {
		cleanup()
		return "", nil, session.spoolTruncated, errors.Join(copyErr, closeSourceErr, closeSnapshotErr, errors.New("live capture snapshot size did not match the recorded byte count"))
	}
	return snapshot.Name(), cleanup, session.spoolTruncated, nil
}

func (session *liveSession) close() error {
	session.spoolMu.Lock()
	defer session.spoolMu.Unlock()
	session.closed = true
	var closeErr error
	if session.spoolFile != nil {
		closeErr = session.spoolFile.Close()
		session.spoolFile = nil
	}
	if session.spoolRoot != nil {
		closeErr = errors.Join(closeErr, session.spoolRoot.Close())
		session.spoolRoot = nil
	}
	if session.spoolDir != "" {
		closeErr = errors.Join(closeErr, os.RemoveAll(session.spoolDir))
		session.spoolDir = ""
	}
	return closeErr
}

// Close releases private spool files owned by the engine.
func (s *Server) Close() error {
	s.sessionMu.Lock()
	sessions := make([]*liveSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessions = nil
	s.sessionOrder = nil
	s.sessionMu.Unlock()
	var closeErr error
	for _, session := range sessions {
		closeErr = errors.Join(closeErr, session.close())
	}
	return closeErr
}
