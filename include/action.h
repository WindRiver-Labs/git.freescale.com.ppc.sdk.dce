#ifndef _ACTION_H_
#define _ACTION_H_

#define MAX_ACTION_NAME 100

struct action;

typedef int (*action_type_cb)(struct action *, void *);

struct action {
  char name[MAX_ACTION_NAME];
  char type_name[MAX_ACTION_NAME];
  action_type_cb action_cb;
  struct action *next;
  
};

struct action* find_action_by_name(const char *name);

void add_action_type_hook(const char *type_name, action_type_cb cb);

#endif
