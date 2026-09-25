#ifndef _NASOT_H
#define _NASOT_H

#include <smpf.h>

/*
 * NASOT -- the 5G NAS (5GMM) task. Everything here is specific to that task or
 * to the one message the harness injects; the reusable SMPF framework layer,
 * and the notes on how it was reversed, are in smpf.h.
 */

MODKIT_FUNCTION_SYMBOL(void, SetMmState, uint32_t, uint32_t, uint32_t, uint32_t)
MODKIT_FUNCTION_SYMBOL(void, NrmmStartProcedure_Wrapper, uint32_t, uint32_t)

/*
 * FakeTestAssist::GetInstance(), from cn_MmFakeTestUtil.hpp.
 *
 * A lazily constructed singleton, so this is only the getter -- the flag a
 * harness wants is byte 0 of the object it returns. Both names come from the
 * constructor's own log line, which reads
 *   "FakeTestAssist() : !!FAKE-TESTHARNESS!! IsFakeTestHarness : %d"
 * and prints exactly that byte. Setting it makes the MM code take its
 * fake-test paths, which is what lets an injected NAS message be processed
 * without a real RRC connection underneath.
 */
MODKIT_FUNCTION_SYMBOL(uint8_t *, FakeTestAssist_GetInstance, void)

/*
 * The MM singletons whose methods the harness calls: cn::mm::NrmmFacade and
 * cn::mm::MmGeneralContext_MacroClass. Both are heap objects built during boot,
 * one per SIM stack, so FirmWire discovers them at run time rather than from a
 * pattern -- see firmwire/vendor/shannon/cxx_instance.py. Their classes are
 * findable in Ghidra by their mangled RTTI names, and every instance stores its
 * vtable pointer at offset 0.
 */
MODKIT_INSTANCE_SYMBOL(uint32_t, NrmmFacade)
MODKIT_INSTANCE_SYMBOL(uint32_t, MmGeneralContext)

/*
 * Message id of MM_RRC_DATA_IND -- the downlink NAS PDU delivery from RRC to
 * MM, and therefore the injection point for 5G NAS fuzzing.
 *
 * To find it on an image: search strings for "!!FAKE-TESTHARNESS!! SEND :
 * MM_RRC_DATA_IND", follow the xref through its TraceEntry into
 * cn_MmFakeTestUtil, and read the first argument of the smpf_CreateMsg call in
 * that branch. Sanity-check it against the msg id layout in smpf.h: the top ten
 * bits must be MM's Ft id, the next ten RRC's, and passing the value to the
 * message-name lookup must yield the string "MM_RRC_DATA_IND".
 *
 * A symbol rather than a constant because Ft ids and message numbers are
 * renumbered between builds.
 */
MODKIT_DATA_SYMBOL(uint32_t, MSG_ID_MM_RRC_DATA_IND)

/*
 * Body of MM_RRC_DATA_IND: a pointer to the raw downlink NAS PDU and its
 * length. This is what smpf_CreateMsg returns a pointer to.
 *
 * The type name is the firmware's own, from the error string
 * "%!EM ERROR : MM_RRC_DATA_IND_T alloc failed"; the field names likewise, from
 * "MM_RRC_DATA_IND pData is NULL, Discard the message!!" and
 * "MM_RRC_DATA_IND_Handler: dataLength: %d". The offsets are confirmed in the
 * handler itself, reachable by searching strings for the first of those and
 * following the TraceEntry xref into cn_NrmmExtHdlrRRC.cpp.
 *
 * Message bodies are per-class -- there is no generic SMPF payload type, as a
 * glance at the other branches of cn_MmFakeTestUtil makes clear -- which is why
 * this lives here and not in smpf.h.
 *
 * The handler frees pData - 8 on every exit path, so pData must point into an
 * SmpfBuf and the harness must not free it.
 */
typedef struct PACKED {
  uint8_t *pData;
  uint16_t dataLength;
} MM_RRC_DATA_IND_T;

#endif // _NASOT_H
