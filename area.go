package gos7

// Copyright 2018 Trung Hieu Le. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

import "fmt"

// Area codes of an S7ANY item (its area byte). The S7-300/400 areas are the
// ones the AG functions above read; the 200-family areas are those of an
// S7-200 and of the PLCs built on it, such as the integrated PLC of a
// SINUMERIK 808D. Wireshark's S7comm dissector (S7COMM_AREA_*) and libnodave
// (daveSysFlags, daveCounter200, daveTimer200) name the same codes.
const (
	AreaPE         = s7areape // process inputs (I, E)
	AreaPA         = s7areapa // process outputs (Q, A)
	AreaMK         = s7areamk // flags (M)
	AreaDB         = s7areadb // data blocks (DB)
	AreaCT         = s7areact // S7 counters (C, Z)
	AreaTM         = s7areatm // S7 timers (T)
	AreaSM         = 0x05     // system flags (SM) of the 200 family
	AreaIECCounter = 0x1E     // IEC counters (C) of the 200 family
	AreaIECTimer   = 0x1F     // IEC timers (T) of the 200 family
)

// Word lengths: the transport size of a request item, which says how its
// element count and start address are read.
const (
	WLBit     = s7wlbit     // one bit; the start is the bit address, byte*8+bit
	WLByte    = s7wlbyte    // bytes; the start is the byte address
	WLCounter = s7wlcounter // S7 counters, 2 bytes each; the start is the counter number
	WLTimer   = s7wltimer   // S7 timers, 2 bytes each; the start is the timer number
	// IEC counters of the 200 family, 3 bytes each: a status byte, then the
	// 16-bit count. The start is the counter number.
	WLIECCounter = 0x1E
	// IEC timers of the 200 family, 5 bytes each: a status byte, then the
	// 32-bit value. The start is the timer number.
	WLIECTimer = 0x1F
)

// ItemError is a data item the CPU answered with a return code other than
// 0xFF (success): the request reached the CPU and the CPU refused that
// item, so nothing of it was read or written. Its text is the one these
// functions have always returned for it.
type ItemError struct {
	// Code is the item's return code, as the CPU sent it: 0x05 address out
	// of range, 0x0A object does not exist, 0x03 access denied, ...
	Code byte
}

func (e *ItemError) Error() string { return ErrorText(CPUError(uint(e.Code))) }

// elementWise reports a word length whose start address is the element
// number (or the bit address) and whose transport size is the word length
// itself, rather than bytes addressed in bits.
func elementWise(wordLen int) bool {
	switch wordLen {
	case s7wlbit, s7wlcounter, s7wltimer, WLIECCounter, WLIECTimer:
		return true
	}
	return false
}

// areaWordLen is the word length an area is always read in, or wordLen.
func areaWordLen(area, wordLen int) int {
	switch area {
	case s7areact:
		return s7wlcounter
	case s7areatm:
		return s7wltimer
	case AreaIECCounter:
		return WLIECCounter
	case AreaIECTimer:
		return WLIECTimer
	}
	return wordLen
}

// checkAreaBuffer refuses an amount the buffer cannot hold, before anything
// is sent.
func checkAreaBuffer(area, amount, wordLen int, buffer []byte) error {
	wordLen = areaWordLen(area, wordLen)
	size := dataSizeByte(wordLen)
	if size == 0 {
		return fmt.Errorf("gos7: word length 0x%02X is not one these functions read or write", wordLen)
	}
	if wordLen == s7wlbit {
		if amount != 1 {
			return fmt.Errorf("gos7: a bit is read or written one at a time, not %d", amount)
		}
	} else if amount < 1 {
		return fmt.Errorf("gos7: amount %d: at least one element", amount)
	}
	if need := amount * size; len(buffer) < need {
		return fmt.Errorf("gos7: %d elements of %d bytes need a buffer of %d, got %d", amount, size, need, len(buffer))
	}
	return nil
}

// AGReadArea reads amount elements of wordLen from any area: the AG
// functions above in one, and the areas they do not cover (the 200
// family's SM, IEC counters and IEC timers). With WLByte, start is the
// byte address and the buffer receives amount bytes; with WLBit, start is
// the bit address (byte*8+bit), amount is 1 and the buffer receives 0 or 1;
// an area of counters or timers is read in its own word length, start being
// the element number and each element its bytes as the CPU sends them.
// dbNumber is used for AreaDB only.
func (mb *client) AGReadArea(area, dbNumber, start, amount, wordLen int, buffer []byte) error {
	if err := checkAreaBuffer(area, amount, wordLen, buffer); err != nil {
		return err
	}
	return mb.readArea(area, dbNumber, start, amount, wordLen, buffer)
}

// AGWriteArea writes amount elements of wordLen to any area, addressed as
// AGReadArea addresses them. Writing an IEC counter or timer is refused:
// how a 200-family CPU takes one has not been confirmed.
func (mb *client) AGWriteArea(area, dbNumber, start, amount, wordLen int, buffer []byte) error {
	if w := areaWordLen(area, wordLen); w == WLIECCounter || w == WLIECTimer {
		return fmt.Errorf("gos7: writing an IEC counter or timer (word length 0x%02X) is not supported", w)
	}
	if err := checkAreaBuffer(area, amount, wordLen, buffer); err != nil {
		return err
	}
	return mb.writeArea(area, dbNumber, start, amount, wordLen, buffer)
}
