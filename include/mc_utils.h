#ifndef __MC_UTILS_H__
#define __MC_UTILS_H__

#include <stdint.h>

int initalize_mc(const char *dprc_name);

struct fsl_mc_io *get_mc_io(void);

uint16_t get_dprc_token(void);
uint16_t get_root_dprc_token(void);

int get_dprc_id(void);

#endif
