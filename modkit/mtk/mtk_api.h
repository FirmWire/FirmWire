#ifndef MTK_API_H
#define MTK_API_H

MODKIT_FUNCTION_SYMBOL(void, dhl_print_string, int, int, int, char *, ...)
MODKIT_FUNCTION_SYMBOL(int, kal_get_task_by_moduleID, int)

// Main structs to send message: peer_buff_struct and local_para_struct.
// More information about them available at: https://comsecuris.com/blog/posts/path_of_least_resistance/

typedef struct peer_buff_struct {
    uint16_t pdu_len;
    uint8_t  ref_count;
    uint8_t  pb_resvered;
    uint16_t free_header_space;
    uint16_t free_tail_space;
    uint8_t  payload[0];
} peer_buff_struct;

typedef struct local_para_struct {
   uint8_t	ref_count; 
   uint8_t  lp_reserved; 
   uint16_t	msg_len;
   char payload[0];
} local_para_struct;

// convience bindings for local_para alloc/free functions


// params: size, resettable, src_file, line
MODKIT_FUNCTION_SYMBOL(void *, construct_int_local_para, uint16_t, uint32_t, const char *, uint32_t)
#define alloc_local_para(size) (construct_int_local_para(size, 0, TASK_NAME, 0))

// params: local_para_ptr, src_file, line
MODKIT_FUNCTION_SYMBOL(void, free_int_local_para, local_para_struct *, const char *, uint32_t)
#define free_local_para(local_para) (free_int_local_para(local_para, TASK_NAME, 0))

// Main interface to send message.
// Params: src_mod_id, dest_mod_id, sap_id, msg_id, local_para_ptr, peer_buf_ptr
MODKIT_FUNCTION_SYMBOL(int, msg_send6, uint16_t, uint16_t, uint16_t, uint16_t, local_para_struct *, peer_buff_struct *)

#endif