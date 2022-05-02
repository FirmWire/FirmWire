#include <task.h>
#include <modkit.h>
#include <hello_world.h>
#include "common.h"
#include "mtk_api.h"

#define PARA_STRUCT_SIZE 0xc
#define PARA_STRUCT_PLSIZE (PARA_STRUCT_SIZE-4)

#define TASK_ID_IDLE 0x3a7
#define TASK_ID_CC   0xb0
#define TEST_MSG_ID  0x25b

void real_main() {
    local_para_struct *_local_para_ptr;
    peer_buff_struct *_peer_buff_ptr = (void *)0;

    while(1) {
        _local_para_ptr = alloc_local_para(PARA_STRUCT_SIZE);
        // memset(&(_local_para_ptr->payload), 0, PARA_STRUCT_PLSIZE);
        // msg_send6(src_mod_id, dst_mod_id, sap_id, msg_id, local_para, peer_buff)
        msg_send6(TASK_ID_IDLE, TASK_ID_CC, 0, TEST_MSG_ID, _local_para_ptr, _peer_buff_ptr);
    }
}
