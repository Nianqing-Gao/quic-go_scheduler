package quic

import (
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/ackhandler"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/quicvarint"
	"sync"
)

type framer interface {
	HasData() bool

	QueueControlFrame(wire.Frame)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)

	AddActiveStream(protocol.StreamID)
	AppendStreamFrames([]ackhandler.Frame, protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount)

	Handle0RTTRejection() error

	HasRetransmission() bool
	
	// SetStreamFlowSize sets the expected flow size for a stream (for flow-size-based DRR)
	SetStreamFlowSize(protocol.StreamID, uint64)
}

type framerI struct {
	mutex sync.Mutex

	streamGetter streamGetter
	version      protocol.VersionNumber

	activeStreams map[protocol.StreamID]struct{}
	streamQueue   []protocol.StreamID

	controlFrameMutex sync.Mutex
	controlFrames  []wire.Frame
	config         *Config
	streamMapPrio map[protocol.StreamID]int // To match priorities with the stream ID
	auxPriorSlice []int
	
	// DRR-specific fields
	deficits     map[protocol.StreamID]int // Deficit counter for each stream
	quantum      int                        // Default quantum value (bytes per round)
	streamQuantums map[protocol.StreamID]int // Per-stream quantum (for flow-size-based DRR)
	streamFlowSizes map[protocol.StreamID]uint64 // Expected flow size for each stream
	drrRoundPosition int // Tracks where we are in the current DRR round
	currentStreamID protocol.StreamID // The stream currently being served (0 means none)
}

var _ framer = &framerI{}

func newFramer(

	streamGetter streamGetter,
	v protocol.VersionNumber,
	config *Config,

) framer {

	quantum := 1200 // Default quantum: ~1 MSS
	if config.DRRQuantum > 0 {
		quantum = config.DRRQuantum
	}
	
	return &framerI{
		streamGetter:    streamGetter,
		activeStreams:   make(map[protocol.StreamID]struct{}),
		version:         v,
		streamMapPrio:   make(map[protocol.StreamID]int),
		config:          config,
		deficits:        make(map[protocol.StreamID]int),
		quantum:         quantum,
		streamQuantums:  make(map[protocol.StreamID]int),
		streamFlowSizes: make(map[protocol.StreamID]uint64),
		drrRoundPosition: 0,
		currentStreamID: 0, // No stream currently being served
	}
}

// Sets the expected flow size for a stream and assigns appropriate quantum
func (f *framerI) SetStreamFlowSize(id protocol.StreamID, flowSize uint64) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	f.streamFlowSizes[id] = flowSize
	
	if len(f.config.FlowSizeThresholds) > 0 && len(f.config.FlowSizeQuantums) > 0 {
		quantum := f.getQuantumForFlowSize(flowSize)
		f.streamQuantums[id] = quantum
		fmt.Printf("[FRAMER] Stream %d: flowSize=%d quantum=%d thresholds=%v\n", 
			id, flowSize, quantum, f.config.FlowSizeThresholds)
	} else {
		fmt.Printf("[FRAMER] Stream %d: NO thresholds/quantums configured!\n", id)
	}
}

// getQuantumForFlowSize returns the quantum for a given flow size based on thresholds
// Small flows get higher quantum (higher priority), large flows get lower quantum (lower priority)
func (f *framerI) getQuantumForFlowSize(flowSize uint64) int {
	// Find the appropriate quantum based on flow size thresholds
	for i, threshold := range f.config.FlowSizeThresholds {
		if flowSize < uint64(threshold) {
			return f.config.FlowSizeQuantums[i]
		}
	}
	// Flow size is larger than all thresholds, use last quantum (lowest priority)
	return f.config.FlowSizeQuantums[len(f.config.FlowSizeQuantums)-1]
}

// getStreamQuantum returns the quantum for a given stream
func (f *framerI) getStreamQuantum(id protocol.StreamID) int {
	// If per-stream quantum is set (flow-size-based), use it
	if quantum, ok := f.streamQuantums[id]; ok {
		return quantum
	}
	// Otherwise use default quantum
	return f.quantum
}

func (f *framerI) HasData() bool {
	f.mutex.Lock()
	hasData := len(f.streamQueue) > 0
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	hasData = len(f.controlFrames) > 0
	f.controlFrameMutex.Unlock()
	return hasData
}

func (f *framerI) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	f.controlFrames = append(f.controlFrames, frame)
	f.controlFrameMutex.Unlock()
}

func (f *framerI) AppendControlFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	f.controlFrameMutex.Lock()
	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(f.version)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}
	f.controlFrameMutex.Unlock()
	return frames, length
}

func (f *framerI) AddActiveStream(id protocol.StreamID) {

	f.mutex.Lock()
	defer f.mutex.Unlock()
	if _, ok := f.activeStreams[id]; !ok {
		f.streamQueue = append(f.streamQueue, id)
		f.activeStreams[id] = struct{}{}


		switch f.config.TypePrio {
		case "abs"://The stream queue is ordered by StreamPrior priorities slice.

			lenQ := len(f.streamQueue)
			prior := 1

			//To assign priority to each slice in a map
			if v, ok := f.streamMapPrio[id]; ok {
				prior=v
			}else{
				fmt.Println("Else: \n",f.streamQueue, lenQ, prior,f.config.StreamPrio)
				if len(f.config.StreamPrio) > 0 {
					prior = f.config.StreamPrio[0]
					f.config.StreamPrio = f.config.StreamPrio[1:] //Delete the used priority for the next stream
				}
				f.streamMapPrio[id] = prior ///To assign priority to each slice in a map
			}

			f.auxPriorSlice = append(f.auxPriorSlice,prior)

			//Absolute priorization: the stream queue is ordered regarding the priorities of the stream (StreamPrio slice) which is also ordered
			posIni := lenQ-1
			newPrior := f.auxPriorSlice[posIni]
			var correctPos int //Correct position of the stream/prior regarding the prior
			for i := lenQ-1; i >= 0 ; i--{
				if  newPrior >= f.auxPriorSlice[i] {
					correctPos=i
				}
			}
			//To insert the stream ID and priority in the correct position
			auxSlice := append(f.auxPriorSlice[:correctPos], append([]int{newPrior}, f.auxPriorSlice[correctPos:posIni]...)...)
			copy(f.auxPriorSlice, auxSlice)

			f.streamQueue = append(f.streamQueue[:correctPos], append([]protocol.StreamID{id}, f.streamQueue[correctPos:posIni]...)...)

		//Weighted fair queueing: the stream IDs are repeated in the stream queue regarding its priority
		case "wfq":
			prior := 1

			if v, ok := f.streamMapPrio[id]; ok {
				prior = v
			} else {
				//If there is priorities in the StreamPrio slice, pick the first one which corresponds to the current stream:
				if len(f.config.StreamPrio) > 0 {
					prior = f.config.StreamPrio[0]
					f.config.StreamPrio = f.config.StreamPrio[1:] //Delete the used priority for the next stream
				}
				f.streamMapPrio[id] = prior ///To assign priority to each slice in a map
			}
			fmt.Println(f.streamMapPrio)

			//Stream ID is replicated in the streamQueue
			for m:= 0; m<prior-1; m++ {
				f.streamQueue = append(f.streamQueue, id)
			}

		case "rr": // stream ID has already been added

		case "drr": // Deficit Round Robin - stream ID has been added, initialize deficit to 0
			if _, ok := f.deficits[id]; !ok {
				f.deficits[id] = 0
			}

		default:
		}
	}

}

/* Modified DRR scheduler: ensures each stream gets multiple packets and no packet sharing */
func (f *framerI) AppendStreamFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount) {

	var length protocol.ByteCount
	var lastFrame *ackhandler.Frame
	f.mutex.Lock()

	// DRR implementation with packet isolation (no stream mixing per packet)
	if f.config.TypePrio == "drr" {
		queueLen := len(f.streamQueue)
		
		if queueLen == 0 {
			f.mutex.Unlock()
			return frames, length
		}
		
		// Reset round position if it's out of bounds (queue changed)
		if f.drrRoundPosition >= queueLen {
			f.drrRoundPosition = 0
			f.currentStreamID = 0 // Reset current stream
		}
		
		var id protocol.StreamID
		
		// Check if we're continuing with a stream from a previous packet
		if f.currentStreamID != 0 {
			// Continue with the current stream if it still has deficit
			id = f.currentStreamID
			
			// Verify the stream still exists in our queue
			streamStillActive := false
			currentIndex := -1
			for i, streamID := range f.streamQueue {
				if streamID == id {
					streamStillActive = true
					currentIndex = i
					f.drrRoundPosition = i
					break
				}
			}
			
			if !streamStillActive || f.deficits[id] <= 0 {
				// Stream finished or deficit exhausted, move to next stream
				f.currentStreamID = 0
				if streamStillActive {
					// Move to next position
					f.drrRoundPosition = (currentIndex + 1) % len(f.streamQueue)
				}
			}
		}
		
		// If no current stream, select the next one
		if f.currentStreamID == 0 {
			streamsChecked := 0
			
			for streamsChecked < len(f.streamQueue) {
				currentIndex := f.drrRoundPosition
				id = f.streamQueue[currentIndex]
				
				// Get the stream
				str, err := f.streamGetter.GetOrOpenSendStream(id)
				if str == nil || err != nil {
					// Stream is done or error, remove it
					fmt.Printf("[DRR] Stream %d: removed (nil or error)\n", id)
					f.removeStreamAtIndex(currentIndex)
					delete(f.activeStreams, id)
					delete(f.deficits, id)
					delete(f.streamQuantums, id)
					delete(f.streamFlowSizes, id)
					
					// Don't increment position since we removed an element
					queueLen = len(f.streamQueue)
					if queueLen == 0 {
						f.mutex.Unlock()
						return frames, length
					}
					if f.drrRoundPosition >= queueLen {
						f.drrRoundPosition = 0
					}
					streamsChecked++
					continue
				}
				
				// Get the quantum for this stream and add to deficit (only when starting this stream)
				streamQuantum := f.getStreamQuantum(id)
				f.deficits[id] += streamQuantum
				
				fmt.Printf("[DRR] Stream %d (pos %d/%d): quantum=%d, deficit=%d (after quantum add)\n", 
					id, currentIndex, queueLen, streamQuantum, f.deficits[id])
				
				// This is now our current stream
				f.currentStreamID = id
				break
			}
			
			// If we couldn't find any valid stream, we're done
			if f.currentStreamID == 0 {
				f.mutex.Unlock()
				return frames, length
			}
		}
		
		// Now send frames from the current stream (fill this entire packet with just this stream)
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		if str == nil || err != nil {
			// Stream disappeared, remove it and reset
			fmt.Printf("[DRR] Stream %d: disappeared during packet creation\n", id)
			for i, streamID := range f.streamQueue {
				if streamID == id {
					f.removeStreamAtIndex(i)
					break
				}
			}
			delete(f.activeStreams, id)
			delete(f.deficits, id)
			delete(f.streamQuantums, id)
			delete(f.streamFlowSizes, id)
			f.currentStreamID = 0
			
			f.mutex.Unlock()
			return frames, length
		}
		
		// Send frames from this stream until packet is full or deficit exhausted
		streamHasMoreData := true
		
		for f.deficits[id] > 0 && streamHasMoreData {
			if protocol.MinStreamFrameSize+length > maxLen {
				// Packet full, but stream still has deficit
				// Keep currentStreamID so we continue with this stream next packet
				fmt.Printf("[DRR] Stream %d: packet full, deficit=%d remaining (will continue next packet)\n", 
					id, f.deficits[id])
				break
			}
			
			remainingLen := maxLen - length
			remainingLen += quicvarint.Len(uint64(remainingLen))
			
			// Limit by deficit - only request as much as we have credit for
			if int(remainingLen) > f.deficits[id] {
				remainingLen = protocol.ByteCount(f.deficits[id])
			}
			
			frame, hasMoreData := str.popStreamFrame(remainingLen)
			streamHasMoreData = hasMoreData
			
			if frame == nil {
				// No frame available right now
				fmt.Printf("[DRR] Stream %d: no frame available\n", id)
				break
			}
			
			frameLength := frame.Length(f.version)
			
			frames = append(frames, *frame)
			length += frameLength
			lastFrame = frame
			f.deficits[id] -= int(frameLength)
			
			fmt.Printf("[DRR] Stream %d: sent frame len=%d, deficit now=%d, hasMore=%v\n", 
				id, frameLength, f.deficits[id], hasMoreData)
			
			if !hasMoreData {
				// Stream has no more data, remove it
				fmt.Printf("[DRR] Stream %d: completed (no more data)\n", id)
				
				for i, streamID := range f.streamQueue {
					if streamID == id {
						f.removeStreamAtIndex(i)
						f.drrRoundPosition = i % max(len(f.streamQueue), 1)
						break
					}
				}
				
				delete(f.activeStreams, id)
				delete(f.deficits, id)
				delete(f.streamQuantums, id)
				delete(f.streamFlowSizes, id)
				f.currentStreamID = 0 // Move to next stream
				
				streamHasMoreData = false
				break
			}
		}
		
		// If deficit is exhausted and stream still has data, move to next stream
		if f.deficits[id] <= 0 && streamHasMoreData {
			fmt.Printf("[DRR] Stream %d: deficit exhausted, moving to next stream\n", id)
			
			// Find current index and move to next
			for i, streamID := range f.streamQueue {
				if streamID == id {
					f.drrRoundPosition = (i + 1) % len(f.streamQueue)
					break
				}
			}
			f.currentStreamID = 0 // Next packet will select a new stream
		}
		
		f.mutex.Unlock()
		if lastFrame != nil {
			lastFrameLen := lastFrame.Length(f.version)
			lastFrame.Frame.(*wire.StreamFrame).DataLenPresent = false
			length += lastFrame.Length(f.version) - lastFrameLen
		}
		return frames, length
	}

	// Original implementation for non-DRR schedulers
	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet
	numActiveStreams := len(f.streamQueue)
	for i := 0; i < numActiveStreams; i++ {
		if protocol.MinStreamFrameSize+length > maxLen || i >= len(f.streamQueue) {
			break
		}
		id := f.streamQueue[0]
		f.streamQueue = f.streamQueue[1:]

		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)
			f.CleanStreamQueueWFQ(id)
			if f.config.TypePrio == "abs" {
				f.config.StreamPrio = f.config.StreamPrio[1:]
			}
			continue
		}
		remainingLen := maxLen - length
		// For the last STREAM frame, we'll remove the DataLen field later.
		// Therefore, we can pretend to have more bytes available when popping
		// the STREAM frame (which will always have the DataLen set).
		remainingLen += quicvarint.Len(uint64(remainingLen))
		frame, hasMoreData := str.popStreamFrame(remainingLen)

		if f.config.TypePrio == "abs" {
			if hasMoreData { // put the stream front in the queue (at the beginning)
				f.streamQueue = append([]protocol.StreamID{id},f.streamQueue...)
			} else { // no more data to send. Stream is not active anymore
				delete(f.activeStreams, id)
				//Delete the priority of the stream in order not to confuse priorities with the arrival of new streams
				f.auxPriorSlice=f.auxPriorSlice[1:]
			}
		}else{ //WFQ or RR
			if hasMoreData { // put the stream back in the queue (at the end)
				f.streamQueue = append(f.streamQueue, id)
			} else { // no more data to send. Stream is not active anymore
				delete(f.activeStreams, id)
				//Delete the ID of the replicated stream
				f.CleanStreamQueueWFQ(id)
			}
		}

		// The frame can be nil
		// * if the receiveStream was canceled after it said it had data
		// * the remaining size doesn't allow us to add another STREAM frame
		if frame == nil {
			continue
		}
		frames = append(frames, *frame)
		length += frame.Length(f.version)
		lastFrame = frame
	}
	f.mutex.Unlock()
	if lastFrame != nil {
		lastFrameLen := lastFrame.Length(f.version)
		// account for the smaller size of the last STREAM frame
		lastFrame.Frame.(*wire.StreamFrame).DataLenPresent = false
		length += lastFrame.Length(f.version) - lastFrameLen
	}

	return frames, length
}

// Helper function to remove stream at specific index
func (f *framerI) removeStreamAtIndex(index int) {
	if index < 0 || index >= len(f.streamQueue) {
		return
	}
	f.streamQueue = append(f.streamQueue[:index], f.streamQueue[index+1:]...)
}

func (f *framerI) CleanStreamQueueWFQ(id protocol.StreamID){
	if f.config.TypePrio == "wfq"{
		for i := len(f.streamQueue)-1; i >= 0; i-- {
			fmt.Println(">>>", f.streamQueue, i)
			if f.streamQueue[i] == id {
				if i == len(f.streamQueue)-1 {
					f.streamQueue = f.streamQueue[:i]
				} else {
					f.streamQueue = append(f.streamQueue[:i], f.streamQueue[i+1:]...)
				}
			}
		}
	}
}

func (f *framerI) Handle0RTTRejection() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.controlFrameMutex.Lock()
	f.streamQueue = f.streamQueue[:0]
	for id := range f.activeStreams {
		delete(f.activeStreams, id)
	}
	// Clean up DRR deficits and flow-size metadata
	for id := range f.deficits {
		delete(f.deficits, id)
	}
	for id := range f.streamQuantums {
		delete(f.streamQuantums, id)
	}
	for id := range f.streamFlowSizes {
		delete(f.streamFlowSizes, id)
	}
	// Reset round position and current stream
	f.drrRoundPosition = 0
	f.currentStreamID = 0
	
	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame:
			return errors.New("didn't expect MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS frame to be sent in 0-RTT")
		case *wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = f.controlFrames[:j]
	f.controlFrameMutex.Unlock()
	return nil
}

// HasRetransmission checks if retransmission queue is empty
// this check is necessary for Delivery Rate Estimation
func (f *framerI) HasRetransmission() bool {
	return f.streamGetter.HasRetransmission()
}

// Helper function to get max of two ints
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
