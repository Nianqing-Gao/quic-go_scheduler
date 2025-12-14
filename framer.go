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

/* Modified for DRR scheduler */
func (f *framerI) AppendStreamFrames(frames []ackhandler.Frame, maxLen protocol.ByteCount) ([]ackhandler.Frame, protocol.ByteCount) {

	var length protocol.ByteCount
	var lastFrame *ackhandler.Frame
	f.mutex.Lock()

	// DRR implementation with flow-size-based quantum assignment
	// Modified to: 1) not round-robin through all streams, 2) remember deficit across calls
	if f.config.TypePrio == "drr" {
		for len(f.streamQueue) > 0 {
			// Check if packet is full before processing next stream
			if protocol.MinStreamFrameSize+length > maxLen {
				break
			}
			
			id := f.streamQueue[0]
			
			// Get the quantum for this stream (either flow-size-based or default)
			streamQuantum := f.getStreamQuantum(id)
			
			// Only add quantum if deficit <= 0 (stream needs new credit)
			// This ensures deficit persists across calls
			if f.deficits[id] <= 0 {
				f.deficits[id] += streamQuantum
				fmt.Printf("[DRR] Stream %d: added quantum=%d, new deficit=%d\n", id, streamQuantum, f.deficits[id])
			} else {
				fmt.Printf("[DRR] Stream %d: continuing with existing deficit=%d\n", id, f.deficits[id])
			}
			
			// Get the stream
			str, err := f.streamGetter.GetOrOpenSendStream(id)
			if str == nil || err != nil {
				// Stream error/closed, remove from queue and clean up
				f.streamQueue = f.streamQueue[1:]
				delete(f.activeStreams, id)
				delete(f.deficits, id)
				delete(f.streamQuantums, id)
				delete(f.streamFlowSizes, id)
				continue
			}
			
			// Send frames while we have deficit and room in packet
			sentAnyData := false
			streamFinished := false
			
			for f.deficits[id] > 0 && protocol.MinStreamFrameSize+length <= maxLen {
				// Check if deficit is large enough to send a valid frame
				if f.deficits[id] < int(protocol.MinStreamFrameSize) {
					// Deficit too small for a valid frame, reset to 0 so it gets fresh quantum next time
					fmt.Printf("[DRR] Stream %d: deficit=%d too small for MinStreamFrameSize, resetting to 0\n", id, f.deficits[id])
					f.deficits[id] = 0
					break
				}
				
				remainingLen := maxLen - length
				remainingLen += quicvarint.Len(uint64(remainingLen))
				
				// Limit by deficit - only request as much as we have credit for
				if int(remainingLen) > f.deficits[id] {
					remainingLen = protocol.ByteCount(f.deficits[id])
				}
				
				frame, hasMoreData := str.popStreamFrame(remainingLen)
				
				if frame == nil {
					// No more frames available right now
					break
				}
				
				frameLength := frame.Length(f.version)
				frames = append(frames, *frame)
				length += frameLength
				lastFrame = frame
				f.deficits[id] -= int(frameLength)
				sentAnyData = true
				
				if !hasMoreData {
					// Stream has finished, mark for removal
					streamFinished = true
					break
				}
			}
			
			// Handle stream state after attempting to send
			if streamFinished {
				// Stream is done, remove it entirely
				f.streamQueue = f.streamQueue[1:]
				delete(f.activeStreams, id)
				delete(f.deficits, id)
				delete(f.streamQuantums, id)
				delete(f.streamFlowSizes, id)
				fmt.Printf("[DRR] Stream %d: finished, removed from queue\n", id)
			} else if _, stillActive := f.activeStreams[id]; stillActive {
				// Check if stream is done when it couldn't send anything
				if !sentAnyData {
					// Stream couldn't send - check if it's actually finished
					testFrame, testHasMore := str.popStreamFrame(protocol.MinStreamFrameSize)
					if testFrame == nil && !testHasMore {
						// Stream is done, remove it
						f.streamQueue = f.streamQueue[1:]
						delete(f.activeStreams, id)
						delete(f.deficits, id)
						delete(f.streamQuantums, id)
						delete(f.streamFlowSizes, id)
						fmt.Printf("[DRR] Stream %d: no data remaining, removed from queue\n", id)
						if protocol.MinStreamFrameSize+length > maxLen {
							break
						}
						continue
					}
					// Stream has more data but couldn't send (waiting) - move to back
					f.streamQueue = append(f.streamQueue[1:], id)
					fmt.Printf("[DRR] Stream %d: no frames ready, moving to back with deficit=%d\n", id, f.deficits[id])
					continue
				}
				
				// Stream sent some data
				if protocol.MinStreamFrameSize+length > maxLen && f.deficits[id] > 0 {
					// Packet is full AND stream still has remaining deficit
					// Keep stream at front to continue in next call
					fmt.Printf("[DRR] Stream %d: packet full, keeping at front with deficit=%d\n", id, f.deficits[id])
					break
				} else {
					// Stream used up deficit or packet not full - move to back
					f.streamQueue = append(f.streamQueue[1:], id)
					fmt.Printf("[DRR] Stream %d: moving to back, deficit=%d\n", id, f.deficits[id])
					// If packet is full, stop processing
					if protocol.MinStreamFrameSize+length > maxLen {
						break
					}
				}
			}
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
