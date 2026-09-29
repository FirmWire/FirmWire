#include <afl.h>
#include <shannon.h>
#include <fuzzers/nasot.h>

const char TASK_NAME[] = "AFL_NASOT\0";

// queue ids are the index into SYM_QUEUE_LIST, which is renumbered per image
static int32_t mmc_qid;
static int32_t nrmm_qid;

typedef struct PACKED {
  uint8_t payload[10];
} Payload_MMC_NRMM_INIT_REQ;

typedef struct PACKED {
  struct qitem_header header;
  Payload_MMC_NRMM_INIT_REQ pl;  
} QItem_MMC_NRMM_INIT_REQ;

#define MM_GMC_INIT_REQ_PL_SIZE 10

void send_MM_GMC_INIT_REQ() {
  struct qitem_mm *item = pal_MemAlloc(
      4, sizeof(struct qitem_header) + MM_GMC_INIT_REQ_PL_SIZE, __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = mmc_qid;
  item->header.op2 = nrmm_qid;
  item->header.size = MM_GMC_INIT_REQ_PL_SIZE;
  item->header.msgGroup = 0x2000;
  memset(item->payload, 0, MM_GMC_INIT_REQ_PL_SIZE);

  pal_MsgSendTo(item->header.op2, item, 2);
}

/*
 * Build an MM_RRC_DATA_IND carrying `buf` as the downlink NAS PDU.
 *
 * smpf_CreateMsg() derives the entire header from the message id, so the two
 * things this function still has to know are message-specific and nothing more:
 * which class to create, and how to fill that class's body.
 *
 * Getting the header from the framework rather than writing it out matters more
 * than it looks. The legacy sender below fills the same fields by hand and gets
 * one of them subtly wrong, and the symptom is not a failure -- the message
 * still arrives and still decodes -- but MM's dispatcher quietly takes a
 * shorter path through its own pre-processing. Whole layers of the target go
 * unfuzzed and nothing in the log says so.
 *
 * Returns the message body, ready for smpf_SendMsg(), or NULL.
 */
static MM_RRC_DATA_IND_T *make_MM_RRC_DATA_IND(uint8_t *buf, uint32_t input_size)
{
  MM_RRC_DATA_IND_T *pl = smpf_CreateMsg(MSG_ID_MM_RRC_DATA_IND, 0x80);
  if (!pl) {
    MODEM_LOG("smpf_CreateMsg FAILED");
    return NULL;
  }

  SmpfBuf *data = (SmpfBuf *)smpf_MemAlloc(input_size + sizeof(SmpfBuf),
                                           __FILE__, __LINE__, 0);
  if (!data) {
    MODEM_LOG("smpf_MemAlloc FAILED");
    return NULL;
  }
  data->refCount = 1;
  data->length = input_size;
  memcpy(data->data, buf, input_size);

  pl->pData = data->data;
  pl->dataLength = (uint16_t)input_size;
  return pl;
}

/*
 * Deliver an MM_RRC_DATA_IND: the 5G analogue of the pal_MemAlloc +
 * pal_MsgSendTo + pal_SmSetEvent sequence fuzzers/lte_rrc.c uses on a legacy
 * task.
 *
 * Two calls, and the same two the firmware's own injector (cn_MmFakeTestUtil)
 * makes. Everything a harness for another SMPF task needs is the same shape:
 * find that task's CreateMsg instantiation and the message id, fill the body,
 * send. See smpf.h for how to find them.
 */
void send_MM_RRC_DATA_IND(uint8_t *buf, uint32_t input_size)
{
  MM_RRC_DATA_IND_T *pl = make_MM_RRC_DATA_IND(buf, input_size);
  if (!pl)
    return;

  uint32_t rc = smpf_SendMsg(pl);
  if (rc)
    MODEM_LOG("smpf_SendMsg returned 0x%x", rc);
}

void send_MMC_NRMM_INIT_REQ()
{
  QItem_MMC_NRMM_INIT_REQ *item = (QItem_MMC_NRMM_INIT_REQ*) pal_MemAlloc(4, sizeof(QItem_MMC_NRMM_INIT_REQ), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = mmc_qid;
  item->header.op2 = nrmm_qid;
  item->header.size = sizeof(QItem_MMC_NRMM_INIT_REQ) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x2000;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.payload[0] = 0;

  pal_MsgSendTo(item->header.op2, item, 2);
}

int fuzz_single_setup()
{
  MODEM_LOG("fuzz_single_setup");
  uart_dump_hex((uint8_t *) &SMPF_TASK_CREATED, 4);

  mmc_qid = queuename2id("MMC");
  nrmm_qid = queuename2id("NRMM");
  if (mmc_qid < 0 || nrmm_qid < 0)
    return 0;

  do {
    pal_Sleep(2);
  } while (*SMPF_TASK_CREATED == 0);

  send_MM_GMC_INIT_REQ();

  return 1;
}

void fuzz_single()
{
  uint32_t input_size;
  uint16_t size;
  
  MODEM_LOG("Getting Work");
  uint8_t *buf = (uint8_t *)getWork(&input_size);
  size = (uint16_t) input_size;

  MODEM_LOG("[+] Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);
  uart_dump_hex((uint8_t *)buf, size); // Print some for testing

  MODEM_LOG("FIRE");
  startWork(0, 0xffffffff); // memory range to collect coverage

  if (!MODKIT_SYMBOL_RESOLVED(NrmmFacade) ||
      !MODKIT_SYMBOL_RESOLVED(MmGeneralContext)) {
    MODEM_LOG("MM instance pointers unresolved, skipping input");
    doneWork(0);
    return;
  }

  uint8_t *IsFakeTestHarness = FakeTestAssist_GetInstance();
  *IsFakeTestHarness = 1;
  NrmmStartProcedure_Wrapper(NrmmFacade, 1);
  SetMmState(MmGeneralContext, 0, 0x4035634, 0);
  MODEM_LOG("Sending MM_RRC_DATA_IND...");
  send_MM_RRC_DATA_IND(buf + 8, input_size - 8);


  doneWork(0);
  MODEM_LOG("WorkDone");
}
