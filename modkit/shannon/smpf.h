#ifndef _SMPF_H
#define _SMPF_H

#include <common.h>
#include <modkit.h>

/*
 * SMPF -- Samsung's C++ modem protocol framework, used by the 5G tasks
 * =============================================================================
 *
 * Legacy Shannon tasks (CC, MM, LteRrc, ...) are plain C on the PAL RTOS: a
 * harness reaches them with pal_MemAlloc + pal_MsgSendTo + pal_SmSetEvent, as
 * fuzzers/lte_rrc.c does. The 5G tasks (NASOT, PSSOT, L3OT, ...) are C++ on
 * SMPF and do not use those queues at all, so that recipe does not port. This
 * header is the SMPF equivalent of shannon.h's PAL declarations.
 *
 * SMPF model, in the terms its own logs use:
 *
 *   Ft ("functional task")  a protocol entity such as MM or RRC. Each has a
 *                           10-bit id and lives in a per-domain object table.
 *   Ot ("object task")      the OS task that owns and runs a set of Fts.
 *   domain                  a stack instance (DSDS), one byte in the header.
 *   msg id                  dst_ft << 22 | src_ft << 12 | msg_num
 *   obj id                  SMPF_OBJID_BASE | ft_id; the logs call it "DestId"
 *
 * Sending is two calls -- see smpf_CreateMsg / smpf_SendMsg below.
 *
 *
 * How this was reversed, and how to redo it on another image
 * -----------------------------------------------------------------------------
 * Nothing here came from a symbol table; the techniques below are what make
 * this tractable, and all of them generalise to the rest of the firmware.
 *
 * 1. Trace entries give you original file names and format strings.
 *    Every log call is log_printf(LogContext *, ...) where LogContext.te points
 *    at a TraceEntry (see shannon.h). Its magic word is "DBT:", +0x10 is the
 *    char *message and +0x18 is the char *file. So from any logging function
 *    you recover the .cpp/.h it was compiled from. That is how SendMsg__ was
 *    placed in SMPF/SMPFramework/Core/Task/Src/smpf_TaskMsg.cpp.
 *
 * 2. Samsung's error strings often name the function.
 *    Searching strings for "return in " finds messages like
 *    "[MSG ERROR]SMPF_COMPOSITE_ERR return in SendMsg__". Grepping strings for
 *    a suspected class ("PbdPcc::", "MmFt::", "smpf_TaskMngr") is usually
 *    faster than reading code.
 *
 * 3. Allocator call sites carry __FILE__ and __LINE__.
 *    smpf_MemAlloc(size, file, line, flags) means every allocation names the
 *    source file of its caller. Decompile a function, look at what it passes
 *    to the allocator, and you have its provenance for free.
 *
 * 4. The firmware ships its own message injector -- use it as the reference.
 *    Search strings for "!!FAKE-TESTHARNESS!!". The xrefs land in
 *    SMPF/Protocol/CoreNetwork/MM/cn_MmFakeTestUtil.cpp, a switch that builds
 *    and sends a dozen different NAS messages. Whatever call sequence it uses
 *    is by definition the supported way to inject one, which is how the
 *    smpf_CreateMsg / smpf_SendMsg pair below was found.
 *
 * 5. Enum names live in pointer tables next to contiguous strings.
 *    Find one member string, then byte-pattern search for its little-endian
 *    address to locate the array that indexes it (see SmpfMsgQType).
 */


/*
 * Queue class a message is delivered on; SmpfMsgHdr.msg_type.
 *
 * Names and order are the firmware's own: the [MSG LOG] lines print a trailing
 * "[SMPF_EXTERNAL]" tag by indexing a 9-entry array of string pointers with
 * this field. Locate that array by searching strings for "SMPF_EXTERNAL", then
 * byte-pattern searching for the little-endian address of "SMPF_URGENT" (the
 * first member); the array sits beside the Ft and Ot count words.
 *
 * smpf_CreateMsg produces SMPF_EXTERNAL; smpf_SendMsg rewrites it to
 * SMPF_BYPASS when the message id carries the bypass flag.
 */
typedef enum PACKED {
  SMPF_URGENT = 0,
  SMPF_HIGH,
  SMPF_SELF,
  SMPF_INTERNAL,
  SMPF_EXTERNAL,
  SMPF_TIMER,
  SMPF_BYPASS,
  SMPF_BYPASS_URG,
  SMPF_USER_CB,
} SmpfMsgQType;

/*
 * The 0x2c byte header every SMPF message carries.
 *
 * Recovered from the header initialiser that smpf_CreateMsg tail-calls: it
 * writes every field in order, so the decompiled listing of that one function
 * is the whole struct. Cross-checked against the fields SendMsg__ reads back.
 *
 * The two object id words are the base constant OR'd with a shift of msg_id.
 * That base is a movw/movt immediate pair at the top of the header initialiser,
 * and is structurally ~(ft_id_mask | special_bits): every bit set except the
 * low 10 that hold the functional task id, and the two mode bits SendMsg__
 * tests to choose between the flat per-domain object table and a tree lookup.
 * So only the Ft id in the low bits actually selects a destination -- which is
 * why a hand-built header with the wrong base still routes, and still misleads.
 *
 * A harness that uses smpf_CreateMsg never touches this -- it is here to make
 * the decompiler output readable and to keep the legacy hand-built sender in
 * fuzzers/nasot.c honest.
 */
typedef struct PACKED {
  uint32_t msg_id;            /* 0x00 dst_ft << 22 | src_ft << 12 | msg_num  */
  uint32_t src_obj_id;        /* 0x04 obj id base | (msg_id >> 0xc)          */
  uint32_t dst_obj_id;        /* 0x08 obj id base | (msg_id >> 0x16)         */
  uint8_t domain_s;           /* 0x0c source domain, from the sending task   */
  uint8_t domain_d;           /* 0x0d dest domain; SendMsg__ zeroes it >=0x40 */
  uint8_t field_0xe[2];
  uint32_t routing;           /* 0x10 second argument of smpf_CreateMsg      */
  uint8_t field_0x14[0xc];
  SmpfMsgQType msg_type;  /* 0x20 */
  uint16_t field_0x21;
  uint8_t field_0x23;
  uint32_t size;              /* 0x24 size of the pool block holding the msg */
  char * msg_name;            /* 0x28 looked up from msg_id; "MM_RRC_DATA_IND" */
} SmpfMsgHdr;

/*
 * Set once the SMPF task set has been created. Messages sent before that are
 * parked in a pending array instead of delivered ("SMPF task is not created
 * yet. Message(%s) is inserted to pending array"), so a harness must spin on
 * this before its first send.
 */
MODKIT_DATA_SYMBOL(uint8_t *, SMPF_TASK_CREATED)

/*
 * Reference-counted data buffer, for message bodies that carry a pointer to
 * bulk data rather than inlining it.
 *
 * Two clues pin the 8 byte prologue: cn_MmFakeTestUtil allocates
 * (length + 8), writes 1 and the length into the first two words, and hands
 * out block + 8; and the receiving handler frees pData - 8 on every exit path.
 * That second half is the important one for a harness -- the receiver owns the
 * buffer, so never free it yourself, and never point pData at a stack or static
 * buffer.
 */
typedef struct PACKED {
  uint32_t refCount;
  uint32_t length;
  uint8_t data[0];
} SmpfBuf;

/*
 * PREPARE. Allocates a message of class `msgId` and fills in its whole
 * SmpfMsgHdr -- ids, domains, queue class, size and name -- then stores
 * `routing` at header +0x10.
 *
 * Returns a pointer to the message *body*, i.e. the bytes after the header, not
 * the message. That is deliberate: callers only ever deal in bodies, and
 * smpf_SendMsg takes the same pointer back.
 *
 * Declared in SMPF/SMPFramework/Export/Public/Task/smpf_TaskUserApiMsgComm.h,
 * per the __FILE__ it passes to the allocator. It is an inlined template, so an
 * image contains one copy per instantiated message size -- pick the one
 * cn_MmFakeTestUtil calls for the class you care about.
 */
MODKIT_FUNCTION_SYMBOL(void *, smpf_CreateMsg, uint32_t msgId, uint32_t routing)

/*
 * ENQUEUE + NOTIFY. Counterpart of smpf_CreateMsg: takes the body pointer it
 * returned, applies the bypass-queue flag carried by the message id, and hands
 * the message to SendMsg__.
 *
 * Returns 0 on success, 0x1f if handed NULL, and passes through 0x22
 * (SMPF_COMPOSITE_ERR, destination could not be resolved) and 0x23
 * (SMPF_OS_ERR, the wakeup failed) from SendMsg__.
 *
 * Find it as the function cn_MmFakeTestUtil calls on the result of
 * smpf_CreateMsg; it is a short wrapper whose only real work is that flag fixup
 * followed by a tail call.
 *
 * That tail call lands in SendMsg__ (smpf_TaskMsg.cpp -- the name is from its
 * own error strings, "SMPF_COMPOSITE_ERR return in SendMsg__"), the single
 * funnel every SMPF message passes through. It resolves the owning Ot and the
 * destination Ft object, calls vtable slot 2 on the Ft to queue the message and
 * slot 2 on the Ot's scheduler to mark it runnable, then signals the Ot's event
 * group unless it is already the running task.
 *
 * Worth knowing about, not worth calling. Open-coding those steps in a harness
 * has been tried and measured: it reproduces one of SendMsg__'s several
 * branches, pins struct offsets, a table stride and a vtable index, and yields
 * a byte-identical trace. The only reason to reach past smpf_SendMsg is to
 * inject beneath the framework -- bypassing the SMPF_TASK_CREATED gate, or
 * targeting an object table entry you overrode yourself.
 */
MODKIT_FUNCTION_SYMBOL(uint32_t, smpf_SendMsg, void * body)

/*
 * SMPF pool allocator, used for message bodies' data buffers.
 *
 * A thin wrapper over pal_MemAlloc that hardcodes a memory type distinct from
 * the one the modkit harnesses use, and blocks and retries instead of returning
 * NULL on exhaustion. The matching free takes only a pointer -- the pool is
 * recovered from the block header -- so the type is an accounting choice, not a
 * correctness constraint.
 *
 * Several identical inlined copies exist; any of them works.
 */
MODKIT_FUNCTION_SYMBOL(void *, smpf_MemAlloc, uint32_t size, const char * szFile, uint32_t line, uint32_t flags)

#endif // _SMPF_H
