#ifndef _PARSER_H_
#define _PARSER_H_

#include <jansson.h>

/* Functions used to decode the JSON file and invoke the component constuctors */

typedef void(*parser_cb)(json_t*);

/* Add a callback for when a node is found */
void parser_register(const char* key, parser_cb cb); 

/* Read in the config file and construct the database */
int parse_config(const char* file);

#endif
