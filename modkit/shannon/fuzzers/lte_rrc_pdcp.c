// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <afl.h>


const char TASK_NAME[] = "AFL_LTE_RRC\0";
struct qitem_lte_rrc {
  struct qitem_header header;
  uint32_t unused;
  uint32_t pdu_type;
  uint32_t pl_size;
  char * asn_pl;
} PACKED;

struct mac_pdu{
  uint32_t extended_msgId;
  uint32_t rrc_ptr;
  uint32_t id;
  uint32_t dst;
  uint32_t src;
} PACKED;


struct qitem_lte_rrc2 {
  struct qitem_header header; //0x0 - 0x8
  uint32_t rb_id; //0x8 - 0xc
  uint32_t pl_len; //0xc- 0x10
  uint32_t pl_ptr; //0x10-0x14
  uint32_t pduSecCheckComp; //0x14-0x18
} PACKED;

struct qitem_lte_MCCH{
  struct qitem_header header;
  uint32_t area;
  uint32_t CC;
  uint32_t pl_len;
  uint32_t pl_ptr;
  uint32_t unk;
} PACKED;

static uint32_t qid;
static struct pal_event_group * group;



int fuzz_single_setup()
{
  qid = queuename2id("LTERRC_PDCP");
  group = eventname2addr("LTE_RRC_");

  return 1;
}
void fuzz_single()
{
    uint32_t input_size;
    uint16_t size;
    MODEM_LOG("[+] Allocating Qitem\n");
    struct qitem_lte_rrc2 *item = pal_MemAlloc(4, sizeof(struct qitem_lte_rrc2), __FILE__, __LINE__);
    if (!item) {
      MODEM_LOG("ALLOC FAILED");
      return;
    }
    MODEM_LOG("[+] Getting Work\n");
    char * buf = getWork(&input_size);
    size = (uint16_t) input_size - 1;

    MODEM_LOG("[+] Received n bytes: ");
    uart_dump_hex((uint8_t *)buf, size); // Print some for testing

    // Max size before size is forced reduced
    if (size > 8188) {
    startWork(0, 0xffffffff); // memory range to collect coverage
    doneWork(0);
    return;
    }

    char * asn_pl = pal_MemAlloc(4, size, __FILE__, __LINE__);


    MODEM_LOG("[+] Filling the qitem\n");
    
    item->header.msgGroup = 0x0; //0x57f8;
    item->header.size = sizeof(struct qitem_lte_rrc2) - sizeof(struct qitem_header);
    item->header.op = MSG_ID_LTE_PDCP_DATA_IND;
  
    item->pl_len = size; 

    uint8_t channel = buf[0] % 4;

    if(channel == 0){
      //MCCH
      item->rb_id = 0x16;
    }
    else if(channel == 1){
      //DL_CCCH
      item->rb_id = 0x0;
    }
    else if(channel == 2){
      //DL_DCCH
      item->rb_id = 0x2;
    }
    else{
      //BCCH_DL_SCH
      item->rb_id = 0x12;
    }

  
    item->pduSecCheckComp = 0x0;

    memcpy(asn_pl, buf+1, size);
    item->pl_ptr = asn_pl;
 
    startWork(0, 0xffffffff); // memory range to collect coverage
    pal_MsgSendTo(qid, item, 2);
    
    MODEM_LOG("[+] Setting Event\n");
    uart_dump_hex((uint8_t *) group, 4);
 
    pal_SmSetEvent(&group, 0x10);
  
    MODEM_LOG("[+] Event set\n");
    
    doneWork(0x0);
    MODEM_LOG("[+] WorkDone\n");
}
