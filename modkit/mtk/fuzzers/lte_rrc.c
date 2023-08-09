#include <task.h>
#include <modkit.h>
#include <afl.h>
#include "common.h"
#include "mtk_api.h"

//#define DEBUG_PRINTS

#define PARA_STRUCT_SIZE 0xc
#define PARA_STRUCT_PLSIZE (PARA_STRUCT_SIZE-4)

#define TASK_ID_IDLE 0x3a7
#define TASK_ID_ERRC 0x298
#define MSG_ID_MCCH 0x57eb
#define MSG_ID_DCCH 0x57f8
#define MSG_ID_CCCH 0x57e3
#define MSG_ID_BCCH 0x57b3

MODKIT_FUNCTION_SYMBOL(char *, prbm_allocate, int, int)
MODKIT_FUNCTION_SYMBOL(char *, prbm_release, int, int, int)
MODKIT_FUNCTION_SYMBOL(char *, errc_lcom_get_emi_address, int, int)
MODKIT_FUNCTION_SYMBOL(void *, get_int_ctrl_buffer, int, char *, int)

MODKIT_FUNCTION_SYMBOL(void, errc_set_current_errc_sim_idx_cntx_ptr, int)

MODKIT_FUNCTION_SYMBOL(void, dhl_report_version2)

// first gets the id?
// second gets some 0/1 value
// third is some kind of idx
//MODKIT_FUNCTION_SYMBOL(char *, errc_lcom_get_free_buffer, char *, char *, char)

// agh we need more fields set :( so we go with this Horrible Thing
// first gets id
// second is the TYPE, we need it to be 0x1, maybe SI type?
// third gets ORed with (id & 0x1f)
// fourth is ???
// fifth is stored somewhere, sometimes +3
// sixth is stored somewhere, sometimes added to fifth, can't be too low, idk
// seventh is stored somewhere
// eighth is the idx passed to errc_lcom_get_free_buffer
// ninth is stored somewhere
MODKIT_FUNCTION_SYMBOL(char *, errc_get_lte_buffer, char *, char, unsigned short *, unsigned int, unsigned int, unsigned int, unsigned int, char, unsigned int)

MODKIT_FUNCTION_SYMBOL(void, errc_spv_write_errc_state, char);

const char TASK_NAME[] = "AFL_LTE_RRC\0";

MODKIT_DATA_SYMBOL(char *, epdcp_errc_mcch_data_buffer_free)
MODKIT_DATA_SYMBOL(char *, epdcp_errc_dcch_data_buffer_free)
MODKIT_DATA_SYMBOL(char *, emac_errc_ccch_data_buffer_free)
MODKIT_DATA_SYMBOL(char *, errc_asn1_mem_free)
	
char *asn_pl;

int fuzz_single_setup()
{
    const char nops[4] = "\x00\x65\x00\x65";
    const char jrcnop[4] = "\xa0\xe8\x00\x65";

    // output version for debugging
    dhl_report_version2();

    // reallocating buffers outside startWork is bad
    // because it doesn't trigger aborts
    // and in persistent mode, OS state can be messed up
    // -> we just allocate a large buffer here
    //asn_pl = prbm_allocate(0x200, 1);
    asn_pl = get_int_ctrl_buffer(0x200, "", 1);

#if 0
    // first param is sim idx, second is emi id
    // note: first ERRC dest msg id is sim 0, second is sim 1, third is sim 0, etc
    char *emi_buffer = errc_lcom_get_emi_address(0, 0);
    dhl_print_string(2, 0, 0, "[+] emi addr %x\n", emi_buffer);
    unsigned int length = 0x20; // 0x3ff max
    // must pass checks in errc_lsys_chk_hw_ctrl_info
    *(unsigned int *)(emi_buffer + 0x0) = 2 | (length << 20);
    *(unsigned int *)(emi_buffer + 0x4) = 0 /* 0x3ff max */ | (0 << 10) /* 3f max */;
#endif

    // stop some functions from calling copro_vrb_release
    // since we didn't allocate the buffer using dpcopro
    memcpy(epdcp_errc_mcch_data_buffer_free, jrcnop, 4);
    memcpy(epdcp_errc_dcch_data_buffer_free, jrcnop, 4);
    memcpy(emac_errc_ccch_data_buffer_free, jrcnop, 4);

    // disable the AsnFreeDecodedWithBlock call in errc_asn1_mem_free
    // we don't care about the double-free on the error path (for MCCH)
    memcpy(errc_asn1_mem_free, jrcnop, 4);

    // 3 is likely ERRC_CONNECTED or LTE_RRC_STATE_CONNECTED?
    errc_set_current_errc_sim_idx_cntx_ptr(0);
    errc_spv_write_errc_state(3);
    errc_set_current_errc_sim_idx_cntx_ptr(1);
    errc_spv_write_errc_state(3);

    return 1;
}

void fuzz_single()
{
    uint32_t input_size;
    uint16_t size;
    local_para_struct *_local_para_ptr;
    peer_buff_struct *_peer_buff_ptr = (void *)0;

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] Getting Work\n");
#endif
    char * buf = getWork(&input_size);
    size = (uint16_t) input_size;

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] Work buf at %x\n", buf);
#endif

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] Received %d bytes\n", size);
#endif

    if (size < 1 + 1) // must be at least one byte apparently, and need the type/pdu also
    {
        startWork(0, 0xffffffff); // memory range to collect coverage
        dhl_print_string(2, 0, 0, "[+] Too small, fail\n");
        doneWork(0);
        return;
    }
    if (size > 0x115 + 1) // max RRC packet size (might even be smaller, but this seems ok)
    {
        startWork(0, 0xffffffff); // memory range to collect coverage
        dhl_print_string(2, 0, 0, "[+] Too large, fail\n");
        doneWork(0);
        return;
    }
    input_size = size - 1;

#if 0
    char *asn_pl;
    unsigned int prbm_alloc_size = 0;
    if (buf[0] == 0x4a)
        prbm_alloc_size = input_size + 4;
    else if (buf[0] != 0x47)
        prbm_alloc_size = input_size;

    if (prbm_alloc_size != 0)
        asn_pl = prbm_allocate(input_size, 1);
    //char *asn_pl = (void *)0x50000000;
#endif
    memset(asn_pl, 0, 0x200);

    unsigned int my_num;

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] calling alloc_local_para\n");
#endif
    switch (buf[0]) {
    case 0x53: // MCCH
        _local_para_ptr = alloc_local_para(0x8 + 0x8);
        memcpy(((char *)_local_para_ptr) + 0x8, &asn_pl, 4);
        memcpy(((char *)_local_para_ptr) + 0xc, &input_size, 4);
        break;
    case 0x4a: // DL_DCCH
        _local_para_ptr = alloc_local_para(0x8 + 0x10);
        memcpy(((char *)_local_para_ptr) + 0x10, &asn_pl, 4);
        my_num = input_size + 4; // last 4 bytes are something else, there's a memcmp /after/ asn1 parsing
        memcpy(((char *)_local_para_ptr) + 0x14, &my_num, 4);
        my_num = 2; // 2 seems to be active state?
        memcpy(((char *)_local_para_ptr) + 0x8, &my_num, 4);
        break;
    case 0x49: // DL_CCCH
        _local_para_ptr = alloc_local_para(0x8 + 0x4);
        memcpy(((char *)_local_para_ptr) + 0x4, &asn_pl, 4); // FIXME: this can't be right...???
        memcpy(((char *)_local_para_ptr) + 0x8, &input_size, 4);
        break;
    case 0x47: // BCCH_DL_SCH
        _local_para_ptr = alloc_local_para(0x8 + 0x10);

        // get through checks in errc_lsys_main
        *((char *)_local_para_ptr + 0xd) = 0x0;
        *((char *)_local_para_ptr + 0xe) = 0x0;

        {
        char bufid = 0x0;
        unsigned short unk1 = 0x0;
        char *lte_buf = errc_get_lte_buffer(&bufid, 1, &unk1, 0, 0, 0, 0, 0, 0);
        *(unsigned int *)(lte_buf + 0x0) = 2 | (input_size << 20);
        *(unsigned int *)(lte_buf + 0x4) = 0 /* 0x3ff max */ | (0 << 10) /* 3f max */;
        asn_pl = (char *)(lte_buf + 0x8);
#ifdef DEBUG_PRINTS
        dhl_print_string(2, 0, 0, "[+] bufid %x, unk1 %x, ptr %x\n", bufid, unk1, lte_buf);
#endif
        *(unsigned short *)((char *)_local_para_ptr + 0x10) = unk1; // AND with 0x1f for buffer id
        }
        break;
    default:
        dhl_print_string(2, 0, 0, "[+] Invalid ASN1 id %x\n", buf[0]);
        startWork(0, 0xffffffff); // memory range to collect coverage
        doneWork(0);
        return;
    }
    //dhl_print_string(2, 0, 0, "[+] filling in para_ptr\n");

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] copying asn payload\n");
#endif
    memcpy(asn_pl, buf+1, input_size);

#ifdef DEBUG_PRINTS
    dhl_print_string(2, 0, 0, "[+] FIRE\n");
#endif
    startWork(0, 0xffffffff); // memory range to collect coverage

    switch (buf[0]) {
    case 0x53:
//#define MCCH_FOR_A10s
#ifdef MCCH_FOR_A10s
        // early builds:
        //msg_send6(TASK_ID_IDLE, TASK_ID_ERRC, 0, 0x57e0, _local_para_ptr, _peer_buff_ptr);
        // as of U5BTCB:
        msg_send6(TASK_ID_IDLE, TASK_ID_ERRC, 0, 0x57e6, _local_para_ptr, _peer_buff_ptr);

#else
        msg_send6(TASK_ID_IDLE, TASK_ID_ERRC, 0, MSG_ID_MCCH, _local_para_ptr, _peer_buff_ptr);
#endif
        break;
    case 0x4a:
        msg_send6(TASK_ID_IDLE, TASK_ID_ERRC, 0, MSG_ID_DCCH, _local_para_ptr, _peer_buff_ptr);
        break;
    case 0x49:
        msg_send6(TASK_ID_IDLE, TASK_ID_ERRC, 0, MSG_ID_CCCH, _local_para_ptr, _peer_buff_ptr);
        break;
    case 0x47:
        // setting the source module to 0x4b avoids double-free in destroy_int_ilm, let's not ask too many questions
        msg_send6(0x4b, TASK_ID_ERRC, 0, MSG_ID_BCCH, _local_para_ptr, _peer_buff_ptr);
        break;
    }

    doneWork(0);

#if 0
    if (prbm_alloc_size)
        prbm_release(asn_pl, prbm_alloc_size, 1);
#endif
}
